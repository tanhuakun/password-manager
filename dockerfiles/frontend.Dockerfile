## Step 1: Build react
FROM node:18-alpine as frontend
WORKDIR /frontend
## copy frontend folder to app
COPY ./frontend .

## Ensure google client id is in env when building
ARG GOOGLE_CLIENT_ID
ENV REACT_APP_GOOGLE_CLIENT_ID=${GOOGLE_CLIENT_ID}

RUN npm --verbose ci
RUN npm run build

## Step 2: Copy to nginx image
FROM nginx:alpine
COPY --from=frontend /frontend/build /var/www/build
COPY ./nginx/nginx.conf /etc/nginx/nginx.conf

