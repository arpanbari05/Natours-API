const multer = require("multer");

// const multerStorage = multer.diskStorage({
//   destination: (req, file, cb) => {
//     cb(null, `public/img/users`);
//   },
//   filename: (req, file, cb) => {
//     cb(null, `user-${req.user._id}-${Date.now()}.jpeg`);
//   },
// });

exports.multerStorage = multer.memoryStorage();

exports.multerFilter = (req, file, cb) => {
  if (file.mimetype.startsWith("image")) cb(null, true);
  else
    cb(
      new AppError(
        `Provided file is not an image. Please provide an image file`
      ),
      false
    );
};