const catchAsync = require("../Utils/catchAsync");
const Tour = require("../Models/tour-model");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);

exports.getCheckoutSession = catchAsync(async (req, res, next) => {
  const tour = await Tour.findById(req.params.tourId);

  const session = await stripe.checkout.sessions.create({
    payment_method_types: ["card"],
    success_url: `${req.protocol}://${req.host}`,
    cancel_url: `${req.protocol}://${req.host}/${tour._id}`,
    customer_email: req.user.email,
    client_reference_id: req.params.tourId,
    line_items: [
      {
        name: tour.name,
        images: [`${req.protocol}://${req.host}/${tour.coverImage}`],
        quantity: 1,
        amount: tour.price,
        currency: "rs",

      }
    ]
  })

  res.status(200).json({
    status: "success",
    session,
  })

});