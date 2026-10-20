import type { ACLEntry } from "./types";

export function aclDraftError(entries: ACLEntry[]) {
  const priorities = new Set<number>();
  for (const entry of entries) {
    if (
      !Number.isSafeInteger(entry.priority) ||
      priorities.has(entry.priority) ||
      entry.ports?.some((p) => !Number.isSafeInteger(p) || p < 1 || p > 65535)
    ) {
      return "优先级必须为不重复的整数，端口为 1–65535。";
    }
    priorities.add(entry.priority);
    if (
      (entry.countries?.length || 0) > 256 ||
      entry.countries?.some((code) => !/^[A-Z]{2}$/.test(code)) ||
      (entry.regions?.length || 0) > 1024 ||
      entry.regions?.some((code) => !/^[A-Z]{2}-[A-Z0-9-]{1,13}$/.test(code))
    ) {
      return "国家代码需为两位大写字母（最多 256 项）；地区需为 COUNTRY-REGION 格式、4–16 个字符（最多 1024 项）。";
    }
    if (
      (entry.countries?.length || entry.regions?.length) &&
      !["deny", "no_match"].includes(entry.geo_unknown_action || "")
    ) {
      return "使用国家或地区条件时，必须明确选择未知来源的处理动作。";
    }
  }
  return "";
}

export function aclDraftEntries(entries: ACLEntry[]) {
  return entries.map((entry) => ({
    ...entry,
    cidrs: entry.cidrs?.length ? entry.cidrs : undefined,
    ports: entry.ports?.length ? entry.ports : undefined,
    countries: entry.countries?.length ? entry.countries : undefined,
    regions: entry.regions?.length ? entry.regions : undefined,
    geo_unknown_action:
      entry.countries?.length || entry.regions?.length
        ? entry.geo_unknown_action
        : undefined,
  }));
}
