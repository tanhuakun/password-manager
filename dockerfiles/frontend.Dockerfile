## Step 1: Build react
FROM node:18-alpine as frontend
WORKDIR /frontend
## copy frontend folder to app
COPY ./frontend .

RUN npm --verbose ci
RUN npm run build

## Step 2: Copy to nginx image
FROM nginx:alpine
COPY --from=frontend /frontend/build /var/www/build
COPY ./nginx/nginx.conf /etc/nginx/nginx.conf
COPY ./scripts/frontend_setup.sh /usr/share/nginx/html/frontend_setup.sh
RUN apk add --no-cache bash
RUN chmod +x /usr/share/nginx/html/frontend_setup.sh

ENTRYPOINT ["/bin/bash", "-c", "/usr/share/nginx/html/frontend_setup.sh && nginx -g \"daemon off;\""]