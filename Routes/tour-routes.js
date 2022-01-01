const express = require("express");
const tourController = require("../Controllers/tour-controller");
const authController = require("../Controllers/auth-controller");

const reviewRouter = require("./review-routes");

const router = express.Router();

// middleware: if there's router something like tours/dk9932/reviews -> review router will be called
router.use("/:tourId/reviews", reviewRouter);

router
  .route("/top-5-tours")
  .get(tourController.topTours, tourController.getAllTours);

router
  .route("/toursWithin/:distance/center/:latlng/unit/:unit")
  .get(tourController.getToursWithIn);

router
  .route("/distance/center/:latlng/unit/:unit")
  .get(tourController.getToursDistance);

router
  .route("/tour-stats")
  .get(
    authController.protect,
    authController.checkRole("admin", "lead-guide"),
    tourController.tourStats
  );
router
  .route("/monthly-plan/:year")
  .get(
    authController.protect,
    authController.checkRole("admin", "lead-guide"),
    tourController.getMonthlyPlan
  );

router
  .route("/")
  .get(tourController.getAllTours)
  .post(
    authController.protect,
    authController.checkRole("admin", "lead-guide"),
    tourController.uploadTourImages,
    tourController.resizeTourImages,
    tourController.createTour
  );

router
  .route("/:id")
  .get(tourController.getTour)
  .patch(
    authController.protect,
    authController.checkRole("admin", "lead-guide"),
    tourController.uploadTourImages,
    tourController.resizeTourImages,
    tourController.updateTour
  )
  .delete(
    authController.protect,
    authController.checkRole("admin", "lead-guide"),
    tourController.deleteTour
  );

module.exports = router;
