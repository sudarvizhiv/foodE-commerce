import jwt from "jsonwebtoken";
import { createError } from "../error.js";

export const verifyToken = async (req, res, next) => {
  try {
    
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return next(createError(401, "You are not authenticated!"));
    }

    
    const token = authHeader.split(" ")[1];
    if (!token) {
      return next(createError(401, "You are not authenticated!"));
    }

    // Verify token
    const decode = jwt.verify(token, process.env.JWT);
    req.user = decode;

    
    return next();
  } catch (err) {
    // Handle specific errors
    if (err.name === "TokenExpiredError") {
      return next(createError(401, "Token expired"));
    }
    if (err.name === "JsonWebTokenError") {
      return next(createError(401, "Invalid token"));
    }
    // Handle other errors
    return next(createError(401, "Authentication failed"));
  }
};
