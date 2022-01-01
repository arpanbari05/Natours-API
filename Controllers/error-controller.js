const AppError = require("../Utils/appError");

const handleCastError = (err) => {
  const message = `Invalid ${err.path}: ${err.stringValue}`;
  return new AppError(message, 400);
};

const handleDuplicateKey = (err) => {
  const message = `Duplicate ${err.keyValue}. Please try another one`;
  return new AppError(message, 400);
};

const handleValidationError = (err) => {
  const message = Object.values(err.errors).map((el) => el.message);
  return new AppError(message.join(". "), 400);
};

const handleTokenExpiredError = () => {
  return new AppError(`Token expired. Please login again.`, 401);
};

const handleJsonWebTokenError = () => {
  return new AppError(`Invalid token. Please login again.`, 401);
};

const errDev = (err, res) => {
  res.status(err.statusCode).json({
    status: err.status,
    message: err.message,
    error: err,
    stack: err.stack,
  });
};

const errProd = (err, res) => {
  console.log(err.message);
  if (err.isTrusted) {
    res.status(err.statusCode).json({
      status: err.status,
      message: err.message,
    });
  } else {
    res.status(500).json({
      status: "error",
      message: "Something went very wrong!",
    });
  }
};

module.exports = (err, req, res, next) => {
  err.statusCode = err.statusCode || 500;
  err.status = err.status || "error";

  if (process.env.NODE_ENV === "development") {
    errDev(err, res);
  } else {
    let error = err;

    if (err.name === "CastError") error = handleCastError(error);
    if (err.code === 11000) error = handleDuplicateKey(error);
    if (err.name === "ValidationError") error = handleValidationError(error);
    if (err.name === "TokenExpiredError") error = handleTokenExpiredError();
    if (err.name === "JsonWebTokenError") error = handleJsonWebTokenError();

    errProd(error, res);
  }
  next();
};
