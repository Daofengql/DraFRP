import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useForm } from "react-hook-form";
import {
  Alert,
  Box,
  Button,
  CircularProgress,
  Paper,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import { APIError, errorMessage, queryClient, request, setCSRF } from "../api";
import type { Session, User } from "../types";

interface AuthOptions {
  registration_enabled: boolean;
  captcha_required: boolean;
}
interface Captcha {
  captcha_id: string;
  image: string;
  expires_at: string;
}
interface Fields {
  username: string;
  password: string;
  confirm_password: string;
  captcha_answer: string;
}

function authError(error: unknown) {
  if (error instanceof APIError) {
    if (error.code === "username_exists") return "用户名已被使用";
    if (error.code === "registration_disabled") return "注册未开放";
    if (error.code === "rate_limited") return "操作过于频繁，请稍后重试";
    if (error.status === 401) return "用户名或密码错误";
  }
  return errorMessage(error);
}

export default function AuthPage() {
  const [params, setParams] = useSearchParams();
  const registering = params.get("auth") === "register";
  const [notice, setNotice] = useState("");
  const [captchaVersion, setCaptchaVersion] = useState(0);
  const [expired, setExpired] = useState(false);
  const {
    register,
    handleSubmit,
    setError,
    setValue,
    getValues,
    reset,
    formState: { errors },
  } = useForm<Fields>();
  const options = useQuery({
    queryKey: ["auth-options"],
    queryFn: ({ signal }) => request<AuthOptions>("/auth/options", { signal }),
    retry: false,
  });
  const captcha = useQuery({
    queryKey: ["auth-captcha", registering, captchaVersion],
    queryFn: ({ signal }) => request<Captcha>("/auth/captcha", { signal }),
    enabled: options.data?.captcha_required === true,
    retry: false,
    gcTime: 0,
    staleTime: Infinity,
    refetchOnWindowFocus: false,
  });
  const refreshCaptcha = () => {
    setValue("captcha_answer", "");
    setExpired(false);
    setCaptchaVersion((v) => v + 1);
  };
  useEffect(() => {
    if (!captcha.data) return;
    const left = Date.parse(captcha.data.expires_at) - Date.now();
    setExpired(left <= 0);
    const timer = window.setTimeout(() => setExpired(true), Math.max(0, left));
    return () => window.clearTimeout(timer);
  }, [captcha.data]);
  const auth = useMutation({
    mutationFn: ({
      registering,
      body,
    }: {
      registering: boolean;
      body: Record<string, string>;
    }) =>
      request<Session | { user: User }>(
        registering ? "/auth/register" : "/auth/login",
        { method: "POST", body: JSON.stringify(body) },
      ),
    onSuccess: (result, submitted) => {
      if (submitted.registering) {
        const username = getValues("username");
        reset({
          username,
          password: "",
          confirm_password: "",
          captcha_answer: "",
        });
        setNotice("注册成功");
        setParams(
          (previous) => {
            const next = new URLSearchParams(previous);
            next.delete("auth");
            return next;
          },
          { replace: true },
        );
        refreshCaptcha();
        return;
      }
      const session = result as Session;
      setCSRF(session.csrf_token);
      queryClient.removeQueries({ predicate: (q) => q.queryKey[0] !== "me" });
      queryClient.setQueryData(["me"], session);
    },
    onError: () => {
      if (options.data?.captcha_required) refreshCaptcha();
    },
  });
  const toggle = () => {
    const username = getValues("username") || "";
    reset({ username, password: "", confirm_password: "", captcha_answer: "" });
    auth.reset();
    setNotice("");
    setParams(
      (previous) => {
        const next = new URLSearchParams(previous);
        if (registering) next.delete("auth");
        else next.set("auth", "register");
        return next;
      },
      { replace: true },
    );
    refreshCaptcha();
  };
  const captchaRequired = options.data?.captcha_required === true;
  const unavailable =
    !options.data || (registering && !options.data.registration_enabled);
  return (
    <Box
      sx={{ minHeight: "100vh", display: "grid", placeItems: "center", p: 2 }}
    >
      <Paper
        component="form"
        variant="outlined"
        sx={{ p: { xs: 3, sm: 5 }, width: "100%", maxWidth: 460 }}
        onSubmit={handleSubmit((data) => {
          if (unavailable) return;
          const username = data.username?.trim() || "";
          if (!username) {
            setError("username", { message: "请输入用户名" });
            return;
          }
          if (!data.password) {
            setError("password", { message: "请输入密码" });
            return;
          }
          if (registering) {
            const size = new TextEncoder().encode(data.password).length;
            if (size < 10 || size > 72) {
              setError("password", {
                message: "密码长度须为 10–72 字节",
              });
              return;
            }
            if (data.password !== data.confirm_password) {
              setError("confirm_password", { message: "两次输入的密码不一致" });
              return;
            }
          }
          const body: Record<string, string> = {
            username,
            password: data.password,
          };
          if (captchaRequired) {
            if (!captcha.data || expired) {
              setError("captcha_answer", { message: "验证码已失效" });
              return;
            }
            if (!data.captcha_answer?.trim()) {
              setError("captcha_answer", { message: "请输入图片中的字符" });
              return;
            }
            body.captcha_id = captcha.data.captcha_id;
            body.captcha_answer = data.captcha_answer.trim();
          }
          setNotice("");
          auth.mutate({ registering, body });
        })}
      >
        <Typography variant="h4" fontWeight={800} color="primary">
          DraFRP
        </Typography>
        <Typography component="h1" variant="h6" sx={{ mt: 1, mb: 3 }}>
          {registering ? "创建账号" : "登录控制台"}
        </Typography>
        <Stack spacing={2}>
          {notice && <Alert severity="success">{notice}</Alert>}
          {options.isPending && (
            <Box role="status" aria-label="读取登录设置">
              <CircularProgress size={24} />
            </Box>
          )}
          {options.error && (
            <Alert
              severity="error"
              action={
                <Button color="inherit" onClick={() => options.refetch()}>
                  重试
                </Button>
              }
            >
              无法读取登录设置：{errorMessage(options.error)}
            </Alert>
          )}
          {registering &&
            options.data &&
            !options.data.registration_enabled && (
              <Alert severity="info">注册未开放</Alert>
            )}
          {auth.error && (
            <Alert severity="error">{authError(auth.error)}</Alert>
          )}
          <TextField
            label="用户名"
            {...register("username")}
            error={!!errors.username}
            helperText={errors.username?.message}
            autoComplete="username"
            required
            autoFocus
            disabled={auth.isPending}
          />
          <TextField
            label="密码"
            {...register("password")}
            error={!!errors.password}
            helperText={
              errors.password?.message ||
              (registering ? "10–72 字节" : undefined)
            }
            type="password"
            autoComplete={registering ? "new-password" : "current-password"}
            required
            disabled={auth.isPending}
          />
          {registering && (
            <TextField
              label="确认密码"
              {...register("confirm_password")}
              error={!!errors.confirm_password}
              helperText={errors.confirm_password?.message}
              type="password"
              autoComplete="new-password"
              required
              disabled={auth.isPending}
            />
          )}
          {captchaRequired && (
            <Stack spacing={1}>
              <Stack
                direction="row"
                spacing={1}
                alignItems="center"
                sx={{ minHeight: 64 }}
              >
                {captcha.data && !captcha.isFetching ? (
                  <Box
                    component="img"
                    alt="图形验证码"
                    src={captcha.data.image}
                    sx={{
                      width: 192,
                      height: 64,
                      maxWidth: "65%",
                      objectFit: "contain",
                      bgcolor: "#fff",
                      borderRadius: 1,
                    }}
                  />
                ) : captcha.isFetching ? (
                  <CircularProgress size={24} aria-label="加载验证码" />
                ) : null}
                <Button
                  type="button"
                  onClick={refreshCaptcha}
                  disabled={auth.isPending || captcha.isFetching}
                >
                  换一张
                </Button>
              </Stack>
              {captcha.error && (
                <Alert severity="error">
                  验证码加载失败：{errorMessage(captcha.error)}
                </Alert>
              )}
              {expired && <Alert severity="warning">验证码已过期</Alert>}
              <TextField
                label="验证码"
                {...register("captcha_answer")}
                error={!!errors.captcha_answer}
                helperText={errors.captcha_answer?.message || "不区分大小写"}
                autoComplete="off"
                inputProps={{ maxLength: 12 }}
                required
                disabled={
                  auth.isPending ||
                  !captcha.data ||
                  captcha.isFetching ||
                  expired
                }
              />
            </Stack>
          )}
          <Button
            type="submit"
            variant="contained"
            size="large"
            disabled={
              auth.isPending ||
              unavailable ||
              (captchaRequired &&
                (!captcha.data || captcha.isFetching || expired))
            }
          >
            {auth.isPending
              ? registering
                ? "创建中…"
                : "登录中…"
              : registering
                ? "注册"
                : "登录"}
          </Button>
          {(registering || options.data?.registration_enabled) && (
            <Button type="button" onClick={toggle} disabled={auth.isPending}>
              {registering ? "返回登录" : "创建账号"}
            </Button>
          )}
        </Stack>
      </Paper>
    </Box>
  );
}
