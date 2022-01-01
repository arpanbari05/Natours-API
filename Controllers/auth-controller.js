const catchAsync = require("../Utils/catchAsync");
const User = require("../Models/user-model");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const AppError = require("../Utils/appError");
const { promisify } = require("util");
const Email = require("./email");
const Review = require("../Models/review-model");

const signToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });
};

const sendTokenCookie = (req, res, token) => {
  const cookieOptions = {
    expires: new Date(
      Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
    ),
    httpOnly: true,
    secure: req.secure || req.headers["x-forwarded-proto"] === "https"
  };

  if (process.env.NODE_ENV == "production") cookieOptions.secure = true;

  res.cookie(`jwt`, token, cookieOptions);
};

exports.signup = catchAsync(async (req, res, next) => {
  const user = await User.create({
    name: req.body.name,
    email: req.body.email,
    password: req.body.password,
    confirmPassword: req.body.confirmPassword,
    photo: req.body.photo,
    role: req.body.role,
  });

  const token = signToken(user._id);

  sendTokenCookie(req, res, token);

  res.status(201).json({
    status: "success",
    token,
    user,
  });
});

exports.login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;

  // 1) Check if the email or password exits
  if (!email || !password) {
    return next(new AppError(`Please provide email and password`, 400));
  }

  // 2) Check if the user exits
  const user = await User.findOne({ email }).select("+password");

  // 3) Check if the password is correct
  if (!user) {
    return next(new AppError(`Invalid email or Password`, 401));
  } else if (!(await user.correctPassword(password, user.password))) {
    return next(new AppError(`Invalid email or Password`, 401));
  }

  // 4) Generate token
  const token = signToken(user._id);

  sendTokenCookie(req, res, token);

  // 5) Send the response
  res.status(200).json({
    status: "success",
    token,
  });
});

exports.protect = catchAsync(async (req, res, next) => {
  // 1) Check if token exits
  let token = req.headers.authorization;
  if (!token) {
    return next(new AppError(`Please provide token in header`, 401));
  }

  token = req.headers.authorization.split(" ")[1];

  // 2) Check if token is valid
  const data = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

  // 3) Check if user exists
  const user = await User.findOne({ _id: data.id });
  if (!user) {
    return next(new AppError(`User didn't found. Please login again`, 401));
  }

  // 4) Check if the password is unchanged
  if (user.changedPasswordAfter(data.iat)) {
    return next(
      new AppError(
        `User has changed the password recently. Please login again`,
        401
      )
    );
  }

  req.user = user;

  next();
});

exports.checkRole = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return next(
        new AppError(`Can't perform this action for this user.`, 403)
      );
    }

    next();
  };
};

exports.forgotPassword = catchAsync(async (req, res, next) => {
  // Check if the user with email exists
  const user = await User.findOne({ email: req.body.email });

  if (!user) {
    return next(new AppError(`User with the provided email not found!`, 404));
  }

  // Generate the token
  const resetToken = user.generateToken();
  user.save({ validateBeforeSave: false });

  // Send email
  const resetURL = `${req.protocol}://${req.get(
    "host"
  )}/api/v1/users/resetPassword/${resetToken}`;

  try {
    await new Email(user, resetURL).sendResetEmail();

    // Send Response
    res.status(200).json({
      status: "success",
      message: "Token sent to email",
    });
  } catch (err) {
    user.passwordResetToken = undefined;
    user.passwordResetTokenExpiresIn = undefined;
    user.save({ validateBeforeSave: false });
    return next(new AppError(`Couldn't send token to email`, 500));
  }
});

exports.resetPassword = catchAsync(async (req, res, next) => {
  // Check if the token is valid
  const hashedToken = crypto
    .createHash("sha256")
    .update(req.params.token)
    .digest("hex");

  const user = await User.findOne({
    passwordChangeToken: hashedToken,
    passwordChangeTokenExpiresIn: { $gt: Date.now() },
  });

  if (!user) {
    return next(new AppError(`Invalid token or token is expired!`));
  }

  // Change the password
  user.password = req.body.password;
  user.confirmPassword = req.body.confirmPassword;
  user.passwordChangeToken = undefined;
  user.passwordChangeTokenExpiresIn = undefined;
  await user.save();

  // Set the passwordChangedAt to current time in the pre middleware

  // Log the user in
  const token = signToken(user._id);

  sendTokenCookie(req, res, token);

  res.status(201).json({
    status: "success",
    token,
  });
});

exports.updatePassword = catchAsync(async (req, res, next) => {
  // Get the current user
  const user = await User.findById(req.user._id).select("+password");

  if (!user) {
    return next(new AppError(`User didn't found. Please login`, 401));
  }

  // Check the current user password with the posted password
  if (!(await user.correctPassword(req.body.currentPassword, user.password))) {
    return next(new AppError(`Incorrect Password`, 401));
  }

  // Update the password
  user.password = req.body.newPassword;
  user.confirmPassword = req.body.confirmNewPassword;
  await user.save();

  // Log the user in
  const token = signToken();

  sendTokenCookie(req, res, token);

  res.status(200).json({
    status: "success",
    token,
  });
});

// Review can only delete or editted by the creator
exports.onlyReviewCreator = async (req, res, next) => {
  const loggedInUser = req.user._id;
  const review = await Review.findById(req.params.id);

  if (!review) {
    return next(
      new AppError(
        `No review found!`,
        404
      )
    );
  }

  if (`${loggedInUser}` !== `${review.user._id}`) {
    return next(
      new AppError(
        `This review is not created by you. You can't edit or delete it.`,
        401
      )
    );
  }

  next();
};