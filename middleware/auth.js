import jwt from "jsonwebtoken";

export function auth(req, res, next) {
  try {
    const token = req.header("x-auth-token");
    jwt.verify(token, "mysecretkey");
    next();
  } catch (error) {
    res.status(401).send(error);
  }
}

export function linkAuth(req, res, next) {
  try {
    const { token } = req.params;
    jwt.verify(token, "mysecretkey");
    next();
  } catch (error) {
    res.status(401).send({ message: "token tampered", ...error });
  }
}
