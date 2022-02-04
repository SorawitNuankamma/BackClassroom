const fetch = require('node-fetch');
const jwt = require('jsonwebtoken');
const User = require('../models/userModel');
const LineUser = require('../models/lineUserModel');
const catchAsync = require('../utils/catchAsync');
const AppError = require('../utils/appError');
const sendEmail = require('../utils/email');
const crypto = require('crypto');
const { promisify } = require('util');

const verifyLineToken = async (token) => {
  const response = await fetch(
    `https://api.line.me/oauth2/v2.1/verify?access_token=${token}`,
    {
      method: 'GET', // *GET, POST, PUT, DELETE, etc.
      mode: 'cors', // no-cors, *cors, same-origin
    }
  );
  return response.json(); // parses JSON response into native JavaScript objects
};

const getLineUserProfile = async (token) => {
  const response = await fetch(`https://api.line.me/v2/profile`, {
    method: 'GET', // *GET, POST, PUT, DELETE, etc.
    mode: 'cors', // no-cors, *cors, same-origin
    headers: {
      Authorization: 'Bearer ' + token,
    },
  });
  return response.json(); // parses JSON response into native JavaScript objects
};

const signToken = (id) => {
  return jwt.sign({ id: id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });
};

const createSendToken = (user, statusCode, res) => {
  const token = signToken(user._id);
  const cookieOptions = {
    expires: new Date(
      Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
    ),
    httpOnly: true,
  };

  if ((process.env.NODE_ENV = 'production')) {
    cookieOptions.secure = true;
  }
  res.cookie('jwt', token, cookieOptions);

  // remove the password
  user.password = undefined;

  res.status(statusCode).json({
    status: 'success',
    token,
    data: {
      user,
    },
  });
};

exports.signup = catchAsync(async (req, res, next) => {
  const newUser = await User.create({
    name: req.body.name,
    email: req.body.email,
    password: req.body.password,
    lineID: req.body.lineID,
  });

  createSendToken(newUser, 201, res);
});

exports.login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;

  // check if email and password is exist
  if (!email || !password) {
    return next(new AppError('Please provide user and password', 400));
  }

  // check if user exist and password correct
  const user = await User.findOne({ email: email }).select('+password');

  if (!user || !(await user.correctPassword(password, user.password))) {
    return next(new AppError('Incorrect email or password', 401));
  }

  createSendToken(user, 200, res);
});

//Middleware function for protect route
exports.protect = catchAsync(async (req, res, next) => {
  let token;

  // get token and check token
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    token = req.headers.authorization.split(' ')[1];
  }
  //console.log(token);

  if (!token) {
    return next(new AppError('You are not logged in!', 401));
  }

  // verification the token
  const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

  // check if user still exist
  const currentUser = await User.findById(decoded.id);
  if (!currentUser) {
    return next(
      new AppError('the token belong to this user is no longer exist', 401)
    );
  }

  // check if user changed password after the token was issue
  if (currentUser.changedPasswordAfter(decoded.iat)) {
    return next(
      new AppError('user password has been change, please login again', 401)
    );
  }

  // GRANT ACCESS TO PROTECTED ROUTE
  req.user = currentUser;
  next();
});

exports.restrictTo = (...roles) => {
  return (req, res, next) => {
    // role [ user, admin]
    if (!roles.includes(req.user.role)) {
      return next(new AppError('you do not have permission', 403));
    }

    next();
  };
};

exports.forgetPassword = catchAsync(async (req, res, next) => {
  // get user base on email
  const user = await User.findOne({ email: req.body.email });
  if (!user) {
    return next(new AppError('no user with that email', 404));
  }

  // generate the random reset token
  const resetToken = user.createPasswordResetToken();
  await user.save({ validateBeforeSave: false });

  // send it to user email
  const resetURL = `${req.protocol}://${req.get(
    'host'
  )}/api/users/resetPassword/${resetToken}`;

  const message = `submit the patch request to change you password to ${resetURL}`;

  try {
    await sendEmail({
      email: user.email,
      subject: 'You password reset token (valid for 10min)',
      message,
    });
    res.status(200).json({
      status: 'success',
      message: 'token send to email',
    });
  } catch (err) {
    user.passwordResetToken = undefined;
    user.passwordResetExpire = undefined;
    await user.save({ validateBeforeSave: false });

    return next(
      new AppError('There was an error sending an email, try again later', 500)
    );
  }
});

exports.resetPassword = async (req, res, next) => {
  // get user base on the token
  const hashedToken = crypto
    .createHash('sha256')
    .update(req.params.token)
    .digest('hex');

  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpire: { $gt: Date.now() },
  });

  // if token has not expire, and there is a user, set the new password
  if (!user) {
    return next(new AppError('Token is invalid or has expired', 400));
  }
  user.password = req.body.password;
  user.passwordResetToken = undefined;
  user.passwordResetExpire = undefined;
  await user.save();

  // update changedPasswordAt property for the user
  // log the user in and send JWT
  createSendToken(user, 200, res);
};

exports.updatePassword = catchAsync(async (req, res, next) => {
  // get user
  let user = req.user;
  user = await User.findById(req.user.id).select('+password');

  // check that current password that user provide is correct
  if (
    !user ||
    !(await user.correctPassword(req.body.password, user.password))
  ) {
    return next(new AppError('Incorrect email or password', 401));
  }

  // update the password
  user.password = req.body.newPassword;
  await user.save();

  // update changedPasswordAt property for the user
  // log the user in and send JWT
  createSendToken(user, 200, res);
});

exports.isLogin = catchAsync(async (req, res, next) => {
  // SEND RESPONSE
  res.status(200).json({
    status: 'success',
  });
});

exports.lineLogin = catchAsync(async (req, res, next) => {
  let token;

  // get token and check token
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    token = req.headers.authorization.split(' ')[1];
  }

  if (!token) {
    return next(new AppError('You are not provide a token!', 401));
  }

  //DEVELOPMENT ONLY
  if (token === process.env.BYPASS_TOKEN) {
    LineUser.findOne({ lineUserId: 'FAKELINEUSERID' }).then((lineUser) => {
      if (!lineUser) {
        return next(new AppError('user not found', 401));
      }

      createSendToken(lineUser, 200, res);
    });
  }
  if (token === process.env.BYPASS_TOKEN2) {
    LineUser.findOne({ lineUserId: 'a1s0andf7us3r' }).then((lineUser) => {
      if (!lineUser) {
        return next(new AppError('user not found', 401));
      }

      createSendToken(lineUser, 200, res);
    });
  }
  //DEVELOPMENT ONLY END

  // verification the token
  // somehow can't figure out this to working with  await
  verifyLineToken(token).then((verifyResult) => {
    if (!verifyResult.client_id) {
      return next(
        new AppError('Invalid token or token are no longer valid', 401)
      );
    }

    //Use line token to get user information
    getLineUserProfile(token).then((userProfile) => {
      // check if line user already exist
      const lineUserId = userProfile.userId;
      LineUser.findOne({ lineUserId: lineUserId }).then((lineUser) => {
        if (!lineUser) {
          return next(new AppError('user not found', 401));
        }

        createSendToken(lineUser, 200, res);
      });
    });
  });
});

exports.lineSignUp = catchAsync(async (req, res, next) => {
  let token;

  // get token and check token
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    token = req.headers.authorization.split(' ')[1];
  }

  if (!token) {
    return next(new AppError('You are not provide a token!', 401));
  }

  // verification the token
  // somehow can't figure out this to working with  await
  verifyLineToken(token).then((verifyResult) => {
    if (!verifyResult.client_id) {
      return next(
        new AppError('Invalid token or token are no longer valid', 401)
      );
    }

    //Use line token to get use information
    getLineUserProfile(token).then((userProfile) => {
      // save user profile in lineUser
      console.log(userProfile);
      LineUser.create({
        name: userProfile.displayName,
        lineUserId: userProfile.userId,
        pictureURL: userProfile.pictureUrl,
      })
        .then((newLineUser) => {
          createSendToken(newLineUser, 200, res);
        })
        .catch((err) => {
          res.status(500).json({
            status: 'fail',
            error: err,
          });
        });
    });
  });
});

//Middleware function for protect route
exports.loginOnly = catchAsync(async (req, res, next) => {
  let token;

  // get token and check token
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    token = req.headers.authorization.split(' ')[1];
  }
  //console.log(token);

  if (!token) {
    return next(new AppError('You are not logged in!', 401));
  }

  // verification the token
  const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

  // check if user still exist
  const currentUser = await LineUser.findById(decoded.id);
  if (!currentUser) {
    return next(
      new AppError('the token belong to this user is no longer exist', 401)
    );
  }

  // GRANT ACCESS TO PROTECTED ROUTE
  req.user = currentUser;

  next();
});
