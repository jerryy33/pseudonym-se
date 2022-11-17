FROM node:lts

RUN mkdir /app
COPY src/management/frontend/package*.json /app
WORKDIR /app
RUN npm ci
COPY src/management/frontend .

CMD ["npm", "run", "dev"]