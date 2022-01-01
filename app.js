const express = require("express");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const rateLimiter = require("express-rate-limit");
const sanitizer = require("express-mongo-sanitize");
const xss = require("xss-clean");
const hpp = require("hpp");

const tourRouter = require("./Routes/tour-routes");
const userRouter = require("./Routes/user-routes");
const reviewRouter = require("./Routes/review-routes");
const AppError = require("./Utils/appError");
const errorController = require("./Controllers/error-controller");

process.on("uncaughtException", () => {
  console.log("Error! Shutting down....");
  process.exit(1);
});

const app = express();

// Parsing json into req.body
app.use(express.json()); // middleware

// Testing middleware
app.use((req, res, next) => {
  req.requestedTime = new Date().toISOString();
  next();
});

const limiter = rateLimiter({
  max: 100,
  windowMs: 60 * 60 * 1000,
  message: "Too many request. Please try again in an hour",
});

// Limiting request from 1 IP
app.use("/api", limiter);

// Sanitizing NoSQL Injection
app.use(sanitizer());

// Sanitizing Cross
app.use(xss());

// Preventing parameter pollution
app.use(
  hpp({
    whitelist: [
      "ratingsAverage",
      "ratingsQuantity",
      "duration",
      "maxGroupSize",
      "difficulty",
      "price",
    ],
  })
);

dotenv.config({
  path: "./config.env",
});

const DB = process.env.DATABASE.replace(
  "<password>",
  process.env.DATABASE_PASSWORD
);

mongoose
  .connect(DB, {
    useNewUrlParser: true,
    useCreateIndex: true,
    useFindAndModify: false,
  })
  .then(() => console.log("Database connect successfully"));

const port = process.env.NODE_ENV || 3000;

app.use("/api/v1/tours", tourRouter);
app.use("/api/v1/users", userRouter);
app.use("/api/v1/reviews", reviewRouter);
app.all("*", (req, res, next) => {
  const err = new AppError(`Can't find ${req.originalUrl} route!`, 404);
  next(err);
});

app.use(errorController);

const server = app.listen(port, () => {
  console.log(`Listening to the requests at port ${port}`);
});

process.on("unhandledRejection", () => {
  console.log("Error! Shutting down....");
  server.close(() => {
    process.exit(1);
  });
});
