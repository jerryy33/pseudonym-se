FROM node:lts

RUN mkdir /app
COPY clients/frontend/package*.json /app
WORKDIR /app
RUN npm ci
COPY clients/frontend .
ARG PORT= 5173
ENV port=${PORT}
CMD ["sh", "-c", "npm run dev -- --port ${port}"]