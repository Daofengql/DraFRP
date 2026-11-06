FROM node:24-alpine AS console
WORKDIR /src/web
COPY web/package*.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
ARG VERSION=dev
ARG COMMIT=unknown
ENV DRAFRP_BUILD_ID=${VERSION}+${COMMIT}
RUN npm run build

FROM golang:1.26.10-alpine AS backend
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ ./cmd/
COPY internal/ ./internal/
COPY --from=console /src/web/dist/ ./internal/webui/dist/
ARG VERSION=dev
ARG COMMIT=unknown
RUN CGO_ENABLED=0 go build -trimpath -tags release -ldflags "-s -w -X drafrp/internal/buildinfo.Version=$VERSION -X drafrp/internal/buildinfo.Commit=$COMMIT" -o /out/drafrp-cloud ./cmd/drafrp-cloud \
 && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X drafrp/internal/buildinfo.Version=$VERSION -X drafrp/internal/buildinfo.Commit=$COMMIT" -o /out/drafrp-edge ./cmd/drafrp-edge \
 && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X drafrp/internal/buildinfo.Version=$VERSION -X drafrp/internal/buildinfo.Commit=$COMMIT" -o /out/drafrp-client ./cmd/drafrp-client

FROM alpine:3.22 AS runtime
RUN apk add --no-cache ca-certificates \
 && adduser -D -u 10001 drafrp \
 && mkdir -p /var/lib/drafrp-client \
 && chown drafrp:drafrp /var/lib/drafrp-client
COPY LICENSE /usr/share/licenses/drafrp/LICENSE
COPY licenses/go/ /usr/share/licenses/drafrp/go/
COPY licenses/npm-production/ /usr/share/licenses/drafrp/npm-production/
COPY licenses/gvisor-LICENSE.txt /usr/share/licenses/drafrp/gvisor-LICENSE.txt
COPY THIRD-PARTY-NOTICES.md /usr/share/doc/drafrp/THIRD-PARTY-NOTICES.md
WORKDIR /app
USER drafrp

FROM runtime AS cloud
COPY --from=backend /out/drafrp-cloud /usr/local/bin/drafrp-cloud
ENTRYPOINT ["drafrp-cloud"]

FROM runtime AS edge
COPY --from=backend /out/drafrp-edge /usr/local/bin/drafrp-edge
ENTRYPOINT ["drafrp-edge"]

FROM runtime AS client
COPY --from=backend /out/drafrp-client /usr/local/bin/drafrp-client
ENTRYPOINT ["drafrp-client"]

FROM edge AS edge-wire
USER root
RUN apk add --no-cache iproute2

FROM client AS client-native
USER root
RUN apk add --no-cache iproute2 iptables

FROM client-native AS client-tun
