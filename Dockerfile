FROM node:12.18-alpine

WORKDIR /usr/src/app

#ENV API=http://18.138.40.25:9091

#ENV PORT=3000

COPY package*.json ./

RUN npm install dotenv

COPY . .

EXPOSE 5005

CMD ["npm", "start"]
