const catchAsync = require("../Utils/catchAsync");
const User = require("../Models/user-model");
const AppError = require("../Utils/appError");
const factory = require("./factory");
const sharp = require("sharp");
const multer = require("multer");
const { multerStorage, multerFilter } = require("../Utils/multerConfig");

const upload = multer({ storage: multerStorage, fileFilter: multerFilter });

exports.uploadUserPhoto = upload.single("photo");

exports.resizePhoto = catchAsync(async (req, res, next) => {
  if (!req.file) return next();

  req.file.filename = `user-${req.user._id}-${Date.now()}.jpeg`;

  await sharp(req.file.buffer)
    .resize(500, 500)
    .toFormat("jpeg")
    .jpeg({ quality: 90 })
    .toFile(`public/img/users/${req.file.filename}`);

  next();
});

exports.noPasswordUpdate = (req, res, next) => {
  // Throw error if the user tries to update password
  if (req.body.password || req.body.confirmPassword) {
    return next(
      new AppError(
        `This route is not for updating password. Please use /update-my-password to update the same`,
        400
      )
    );
  }

  next();
};

exports.updateUser = catchAsync(async (req, res, next) => {
  // Update the current user
  if (req.file) req.body.photo = req.file.filename;
  const tour = await User.findByIdAndUpdate(req.user._id, req.body);

  res.status(200).json({
    status: "success",
    tour: { ...tour._doc },
  });
});

exports.deleteUser = catchAsync(async (req, res) => {
  // Change the user to inactive
  await User.findByIdAndUpdate(req.user._id, { active: false });

  res.status(204).json({
    status: "success",
  });
});

exports.getMe = (req, res, next) => {
  req.params.id = req.user._id;
  next();
};

exports.getAllUsers = factory.getAll(User);
exports.getUser = factory.getOne(User);
exports.deleteUserPer = factory.deleteOne(User);
