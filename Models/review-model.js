const mongoose = require("mongoose");
const Tour = require("./tour-model");

const reviewSchema = mongoose.Schema(
  {
    review: {
      type: String,
      required: [true, "Review must have a review"],
    },
    ratings: {
      type: Number,
      min: [1, "Review rating should be more or equal to 1"],
      max: [5, "Review rating should be less or equal to 5"],
      default: 4.5,
    },
    createdAt: {
      type: Date,
      default: Date.now(),
    },
    tour: {
      type: mongoose.Schema.ObjectId,
      ref: "Tour",
      required: [true, "Review must have a tour"],
    },
    user: {
      type: mongoose.Schema.ObjectId,
      ref: "User",
      required: [true, "Review must have a user"],
    },
  },
  {
    toJSON: { virtual: true },
    toObject: { virtual: true },
  }
);

// Indexing and unique so that a user can only post 1 review on a single tour
reviewSchema.index({ tour: 1, user: 1 }, { unique: true });

// Query middleware to transform a query before it is executed
reviewSchema.pre(/^find/, function (next) {
  this.populate({
    path: "user",
    select: "name photo",
  });

  next();
});

reviewSchema.pre(/^findOneAnd/, async function (next) {
  this.r = await this.findOne();
  console.log(this.r);
  next();
});

reviewSchema.post(/^findOneAnd/, function () {
  this.r.constructor.calcAverageSumRatings(this.r.tour);
});

// static function
reviewSchema.statics.calcAverageSumRatings = async function (tourId) {
  const stats = await this.aggregate([
    {
      $match: { tour: tourId },
    },
    {
      $group: {
        _id: "$tour",
        nRatings: { $sum: 1 },
        avgRatings: { $avg: "$ratings" },
      },
    },
  ]);

  console.log(stats);

  if (stats.length > 0) {
    await Tour.findByIdAndUpdate(tourId, {
      ratingsAverage: stats[0].avgRatings,
      ratingsQuantity: stats[0].nRatings,
    });
  } else {
    await Tour.findByIdAndUpdate(tourId, {
      ratingsAverage: 4.5,
      ratingsQuantity: 0,
    });
  }
};

// document middleware POST, updating the tour averageRatings and ratingsQuantity
reviewSchema.post("save", function () {
  // calling static function on reviewModel
  this.constructor.calcAverageSumRatings(this.tour);
});

const reviewModel = mongoose.model("Review", reviewSchema);

module.exports = reviewModel;
