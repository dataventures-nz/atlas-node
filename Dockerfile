FROM node:latest

WORKDIR /home/app

ADD package.json /home/app
RUN npm install
ADD . /home/app
RUN cd /home/app/ ; touch .env

CMD ["npm", "start"]

EXPOSE 3000
