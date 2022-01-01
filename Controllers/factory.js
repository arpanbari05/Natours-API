const catchAsync = require("../Utils/catchAsync");
const AppError = require("../Utils/appError");
const APIFeatures = require("../Utils/apiFeatures");

exports.deleteOne = (Model) =>
  catchAsync(async (req, res, next) => {
    const doc = await Model.findByIdAndDelete(req.params.id);

    if (!doc) {
      return next(new AppError(`Can't find that document`, 404));
    }

    res.status(204).json({
      status: "success",
      data: null,
    });
  });

exports.updateOne = (Model) =>
  catchAsync(async (req, res, next) => {
    const doc = await Model.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
      runValidators: true,
    });

    if (!doc) {
      return next(
        new AppError(`Can't find document with ${req.params.id}!`, 404)
      );
    }

    res.status(200).json({
      status: "success",
      data: {
        ...doc._doc,
      },
    });
  });

exports.createOne = (Model) =>
  catchAsync(async (req, res, next) => {
    const doc = await Model.create(req.body);

    res.status(201).json({
      status: "success",
      data: {
        ...doc._doc,
      },
    });
  });

exports.getOne = (Model) =>
  catchAsync(async (req, res, next) => {
    const doc = await Model.findById(req.params.id).populate({
      path: "reviews",
    });

    if (!doc) {
      return next(
        new AppError(`Can't find document with ${req.params.id}!`, 404)
      );
    }

    if (doc.$$populatedVirtuals) {
      doc.reviews = doc.$$populatedVirtuals.reviews;
    }

    res.status(200).json({
      status: "success",
      data: {
        doc,
      },
    });
  });

exports.getAll = (Model) =>
  catchAsync(async (req, res, next) => {
    const filter = req.params.tourId ? { tour: req.params.tourId } : {};

    // Api Features
    const features = new APIFeatures(Model.find(filter), req.query)
      .filter()
      .sort()
      .limitFields()
      .paginate();

    // Executing Query
    const doc = await features.query;

    res.status(200).json({
      status: "success",
      results: doc.length,
      data: {
        doc,
      },
    });
  });
