FROM node:lts

RUN mkdir /app
COPY management/frontend/package*.json /app
WORKDIR /app
RUN npm ci
COPY management/frontend .

CMD ["npm", "run", "dev"]