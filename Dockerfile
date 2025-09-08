FROM node:22-alpine AS builder

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

# Копируем папку public (для логотипа)
COPY public ./public

# Собираем проект
RUN npm run build

# Копируем шаблоны писем, если они не компилируются
RUN cp -r src/templates dist/templates

# Можно удалить, если только для отладки
# RUN ls -la dist/templates

# ✅ Копируем и public в dist — можно так, если хочешь потом класть в dist
RUN cp -r public dist/public


# Кладём ВСЕ артефакты EUSign в dist/eusign (регистр неважен)
RUN mkdir -p dist/eusign \
 && find src/eusign -maxdepth 1 -type f \
      \( -iname '*.cer' -o -iname '*.pem' -o -iname '*.dat' -o -iname 'CAs*.json' -o -iname 'CACertificates*.p7b' -o -iname '*.js' \) \
      -exec cp {} dist/eusign/ \; \
 && ls -la dist/eusign   

 
# --- Runtime stage ---
FROM node:22-alpine

WORKDIR /app

# ❗️ Добавляем сертификаты для TLS
RUN apk add --no-cache ca-certificates openssl \
    && update-ca-certificates

# Копируем сборку
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package*.json ./

# Копируем клиент, если нужно
COPY --from=builder /app/client ./client

# ❗️ НЕ ХВАТАЕТ: public
COPY --from=builder /app/public ./public

EXPOSE 3002

CMD ["node", "dist/main.js"]



