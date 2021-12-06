const AppError = require('../utils/appError');

const handleJWTExpiredError = () =>
  new AppError('your token has expire, please login again', 401);

const handleJWTError = () =>
  new AppError('Invalid token, please login again', 401);

const handleDuplicateFieldsDB = (err) => {
  const message = `Duplicate value`;
  let error = new AppError(message, 400);
  return error;
};

const handleCastErrorDB = (err) => {
  const message = `Invalid ${err.path}: ${err.value}`;
  let error = new AppError(message, 400);
  return error;
};

const handleValidationErrorDB = (err) => {
  const errors = Object.values(err.errors).map((el) => el.message);

  const message = `Invalid data input ${errors.join(', ')}`;
  let error = new AppError(message, 400);
  return error;
};

const sendErrorDev = (err, res) => {
  res.status(err.statusCode).json({
    status: err.status,
    error: err,
    message: err.message,
    stack: err.stack,
  });
};

const sendErrorProd = (err, res) => {
  // Operational Error
  if (err.isOperational) {
    res.status(err.statusCode).json({
      status: err.status,
      message: err.message,
    });
    // Programming error
  } else {
    // send error message
    res.status(500).json({
      status: 'error',
      stack: 'Something went wrong',
    });
  }
};

module.exports = (err, req, res, next) => {
  err.statusCode = err.statusCode || 500;
  err.status = err.status || 'error';

  if (process.env.NODE_ENV === 'development') {
    sendErrorDev(err, res);
  } else if (process.env.NODE_ENV === 'production') {
    let error = { ...err };
    //console.log(err);

    if (err.name == 'CastError') {
      error = handleCastErrorDB(error);
    }
    if (err.code == 11000) {
      error = handleDuplicateFieldsDB(error);
    }
    if (err.name == 'ValidationError') {
      error = handleValidationErrorDB(error);
    }
    if (err.name == 'JsonWebTokenError') {
      error = handleJWTError();
    }
    if (err.name == 'TokenExpiredError') {
      error = handleJWTExpiredError();
    }

    sendErrorProd(error, res);
  }
};
