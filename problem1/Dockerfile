FROM node:18.14.0-alpine

WORKDIR /usr/src/app

COPY package*.json ./

RUN yarn

COPY . .

CMD ["node", "./index.js"]
