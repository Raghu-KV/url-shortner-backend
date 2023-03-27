import express from "express";
import { MongoClient } from "mongodb";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import cors from "cors";
import { ObjectId } from "mongodb";
import nodemailer from "nodemailer";

import { auth, linkAuth } from "./middleware/auth.js";
const app = express();

//connecting mongodb____________________
const MONGO_URL =
  "mongodb+srv://raghutwo:welcome123@cluster0.4gd3qjn.mongodb.net";
const client = new MongoClient(MONGO_URL);
await client.connect();
console.log("mongo connected");
//_______________________________________

const PORT = 4000;
app.use(express.json());
app.use(cors());

app.get("/", (req, res) => {
  res.send("express working successfully");
});

app.get("/who-has-logged-in", auth, async (req, res) => {
  const token = req.header("x-auth-token");
  try {
    const data = await client
      .db("url-shortner")
      .collection("users")
      .findOne({ token: token });
    res.send({ userName: data.userName });
  } catch {
    res.status(401).send({ message: "token tampered" });
  }
});

app.post("/sign-up", async (req, res) => {
  const data = req.body;

  //check user name available______
  const usernameCheck = await client
    .db("url-shortner")
    .collection("users")
    .findOne({ userName: data.userName });

  console.log(usernameCheck);
  if (usernameCheck) {
    res.status(401).send({ message: "user name already exits try login" });
  } else if (data.password.length < 7) {
    res
      .status(401)
      .send({ message: "password should be at least 8 character" });
  } else {
    //hsah the password
    const password = data.password;
    const NO_OF_ROUNDS = 10;
    const salt = await bcrypt.genSalt(NO_OF_ROUNDS);
    const hashedPassword = await bcrypt.hash(password, salt);
    //____________________

    //get jwt token___________
    const token = jwt.sign({ id: hashedPassword }, "mysecretkey");
    //________________________
    const patchedData = { ...data, token: token, password: hashedPassword };

    const result = await client
      .db("url-shortner")
      .collection("users")
      .insertOne(patchedData);

    res.send({ userName: data.userName, token: token });
  }
});

app.post("/log-in", async (req, res) => {
  const data = req.body;

  const checkUser = await client
    .db("url-shortner")
    .collection("users")
    .findOne({ userName: data.userName });

  if (!checkUser) {
    res.status(401).send({ message: "invalid username or passworrd" });
  } else {
    const db_password = checkUser.password;
    const checkPass = await bcrypt.compare(data.password, db_password);
    console.log(checkPass);

    if (checkPass) {
      const token = jwt.sign({ id: checkUser._id }, "mysecretkey");

      const updateToken = await client
        .db("url-shortner")
        .collection("users")
        .updateOne(
          { userName: checkUser.userName },
          { $set: { token: token } }
        );

      res.send({ userName: checkUser.userName, token: token });
    } else {
      res.status(401).send({ message: "invalid username or password" });
    }
  }
});

app.post("/forget-password", async (req, res) => {
  const { email } = req.body;

  const checkEmail = await client
    .db("url-shortner")
    .collection("users")
    .findOne({ email: email });

  console.log(checkEmail);

  if (checkEmail) {
    const token = jwt.sign({ id: checkEmail._id }, "mysecretkey", {
      expiresIn: "10m",
    });

    let config = {
      service: "gmail",
      auth: {
        user: "raghunandanv19@gmail.com",
        pass: "iwjhsijcarsdnwni",
      },
    };

    let transpoter = nodemailer.createTransport(config);

    let message = {
      from: "raghunandanv19@gmail.com",
      to: checkEmail.email,
      subject: "PASSWORD RESET LINK",
      text: `http://localhost:3000/forget-password/${checkEmail._id}/${token}`,
      html: `<h1>Password reset link </h1> <p>http://localhost:3000/forget-password/${checkEmail._id}/${token}</p> <h3>the link expires in 10 minitus </h3>`,
    };

    await transpoter.sendMail(message);

    res.send({
      message: "password link has been sent to your mail",
      // theLink: `http://localhost:3000/forget-password/${checkEmail._id}/${token}`,
    });
  } else {
    res.status(401).send({ message: "the Email does not exists" });
  }
});

app.post("/forget-password/:id/:token", linkAuth, async (req, res) => {
  const { id } = req.params;
  const { password } = req.body;
  console.log(id);

  const generateHashedPassword = async (password) => {
    const NO_OF_ROUNDS = 10;
    const salt = await bcrypt.genSalt(NO_OF_ROUNDS);
    const hashedPassword = await bcrypt.hash(password, salt);
    return hashedPassword;
  };

  const hashPassword = await generateHashedPassword(password);

  const findUserById = await client
    .db("url-shortner")
    .collection("users")
    .findOne({ _id: new ObjectId(id) });

  if (findUserById) {
    await client
      .db("url-shortner")
      .collection("users")
      .updateOne(
        { _id: new ObjectId(id) },
        { $set: { password: hashPassword } }
      );
    res.send({ message: "password changed successfully" });
  } else {
    res.status(401).send({ message: "id tampared" });
  }
});

app.listen(PORT, () => console.log(`listening to ${PORT}`));
