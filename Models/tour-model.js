const mongoose = require("mongoose");
const slugify = require("slugify");

const tourSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, "A tour must have a name"],
      unique: true,
      minLength: [
        10,
        "A tour name must be more than or equal to 10 characters",
      ],
      maxLength: [40, "A tour name must be smaller or equal to 40 characters"],
    },
    ratingsAverage: {
      type: Number,
      default: 4.5,
      min: [1, "A tour ratingsAverage should be bigger than or equal to 1"],
      max: [5, "A tour ratingsAverage should be smaller than or equal to 5"],
    },
    ratingsQuantity: {
      type: Number,
    },
    slug: { type: String },
    secretTour: { type: Boolean, default: false },
    price: {
      type: Number,
      required: [true, "A tour must have price"],
    },
    priceDiscount: {
      type: Number,
      validate: {
        validator: function (val) {
          return val < this.price;
        },
        message:
          "Price Discount: [{VALUE}] should be smaller than regular price",
      },
    },
    difficulty: {
      type: String,
      enum: {
        values: ["easy", "difficult", "medium"],
        message: "Difficulty must be either easy, difficult or medium",
      },
    },
    duration: {
      required: [true, "A tour must have a duration"],
      type: Number,
    },
    summary: {
      type: String,
      required: [true, "A tour must have a summary"],
    },
    description: {
      type: String,
    },
    maxGroupSize: {
      type: Number,
    },
    createdAt: {
      type: Date,
      default: Date.now(),
    },
    startDates: [Date],
    imageCover: {
      type: String,
      required: [true, "A tour must have a imageCover"],
    },
    images: [String],
    startLocation: {
      type: {
        type: String,
        enum: {
          values: ["Point"],
          message: "Start location type can only be Point",
        },
      },
      coordinates: [Number],
      description: String,
      address: String,
    },
    locations: [
      {
        description: String,
        type: {
          type: String,
          enum: {
            values: ["Point"],
            message: "Start location type can only be Point",
          },
        },
        coordinates: [Number],
        day: Number,
      },
    ],
    guides: [
      {
        type: mongoose.Schema.ObjectId,
        ref: "User",
      },
    ],
  },
  {
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

tourSchema.index({ price: 1, ratingsAverage: -1 });
tourSchema.index({ slug: 1 });
tourSchema.index({ startLocation: "2dsphere"})

tourSchema.virtual("durationWeeks").get(function () {
  return this.duration / 7;
});

tourSchema.virtual("reviews", {
  ref: "Review",
  foreignField: "tour",
  localField: "_id",
});

tourSchema.pre("save", function (next) {
  this.slug = slugify(this.name, { lower: true });
  next();
});

// tourSchema.post("save", function(doc, next) {
//   console.log(doc);
//   next();
// })

tourSchema.pre(/^find/, function (next) {
  this.find({ secretTour: { $ne: true } });
  next();
});

tourSchema.pre(/^find/, function (next) {
  this.populate({
    path: "guides",
    select: "-__v -passwordChangedAt",
  });

  next();
});

const Tour = mongoose.model("Tour", tourSchema);

module.exports = Tour;
