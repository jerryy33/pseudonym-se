FROM node:lts

RUN mkdir /app
COPY clients/frontend/package*.json /app
WORKDIR /app
RUN npm ci
COPY clients/frontend .
CMD ["npm", "run", "dev"]