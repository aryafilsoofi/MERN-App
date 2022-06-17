const jwt = require("jsonwebtoken");
const asyncHandler = require("express-async-handler");
const User = require("../models/userModel");

const protect = asyncHandler(async (req, res, next) => {
  let token;
  //Check for authorization header
  //Make sure its a Bearer token
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer")
  ) {
    try {
      //Get token from Header and assign it
      token = req.headers.authorization.split(" ")[1];

      //Decode & verify token and assign it
      const decoded = jwt.verify(token, process.env.JWT_SECRET);

      //Get user from the decoded token and assign it
      req.user = await User.findById(decoded.id).select("-password");

      //Calls next piece of middleware
      next();
    } catch (error) {
      //If anything goes wrong, throw and error
      console.log(error);
      res.status(401);
      throw new Error("Not authorized");
    }
  }
  if (!token) {
    res.status(401);
    throw new Error("Not authorized - No token");
  }
});

module.exports = { protect };
