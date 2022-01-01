const reviewController = require("../Controllers/review-controller");
const authController = require("../Controllers/auth-controller");
const express = require("express");

const router = express.Router({ mergeParams: true });

router
  .route("/")
  .get(reviewController.getAllReviews)
  .post(
    authController.protect,
    authController.checkRole("user"),
    reviewController.setTourUserIds,
    reviewController.createReview
  );

router
  .route("/:id")
  .get(reviewController.getReview)
  .patch(
    authController.protect,
    authController.checkRole("user"),
    authController.onlyReviewCreator,
    reviewController.updateReview
  )
  .delete(
    authController.protect,
    authController.checkRole("user"),
    authController.onlyReviewCreator,
    reviewController.deleteReview
  );

module.exports = router;
