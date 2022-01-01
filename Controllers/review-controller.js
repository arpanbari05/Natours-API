const Review = require("../Models/review-model");
const factory = require("./factory");

exports.setTourUserIds = (req, res, next) => {
  req.body.tour = req.body.tour || req.params.tourId;
  req.body.user = req.body.user || req.user._id;

  next();
};

exports.getAllReviews = factory.getAll(Review);
exports.getReview = factory.getOne(Review);
exports.createReview = factory.createOne(Review);
exports.updateReview = factory.updateOne(Review);
exports.deleteReview = factory.deleteOne(Review);
