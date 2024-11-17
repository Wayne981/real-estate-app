import express from "express";
import authRouter from "./routes/auth.route.js";  // Make sure path is correct
import postRouter from "./routes/post.route.js";
import dotenv from 'dotenv';

dotenv.config();

const app = express();

app.use(express.json());

app.use("/api/auth", authRouter);
app.use("/api/posts", postRouter);

app.listen(8800, () => {
    console.log("Server is running on port 8800");
});