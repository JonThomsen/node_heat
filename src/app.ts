import "dotenv/config";
import express from "express";
import http from "http";
import cors from "cors";
import { Server } from "socket.io";

import { router } from "./routes";

const app = express();
app.use(cors())

const serverHttp = http.createServer(app);

//cors responsável por permitir ou barrar as requisições
const io = new Server(serverHttp, {
  cors: {
    origin: "*"
  }
});

io.on("connection", Socket => {
  console.log(`Usuário conectado no socket ${Socket.id}`);
})

app.use(express.json());

app.use(router);

//simular o que o front e o mobile vão fazer
//localhost:4000/github

app.get("/github", (request, response) => {
  response.redirect(`https://github.com/login/oauth/authorize?client_id=${process.env.
    GITHUB_CLIENT_ID}`
  );
});

app.get("/signin/callback", (request, response) => {
  const { code } = request.query;

  return response.json(code);
});

export { serverHttp, io };