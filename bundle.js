var $8dMYy$express = require("express");
var $8dMYy$mongoose = require("mongoose");
var $8dMYy$dotenv = require("dotenv");
var $8dMYy$expressratelimit = require("express-rate-limit");
var $8dMYy$expressmongosanitize = require("express-mongo-sanitize");
var $8dMYy$xssclean = require("xss-clean");
var $8dMYy$hpp = require("hpp");
var $8dMYy$multer = require("multer");
var $8dMYy$sharp = require("sharp");
var $8dMYy$slugify = require("slugify");
var $8dMYy$jsonwebtoken = require("jsonwebtoken");
var $8dMYy$crypto = require("crypto");
var $8dMYy$util = require("util");
var $8dMYy$validator = require("validator");
var $8dMYy$bcryptjs = require("bcryptjs");
var $8dMYy$nodemailer = require("nodemailer");








var $fea4391203025921$exports = {};

var $0e727cd460af10a7$export$b4cc9a7f549f80be;
var $0e727cd460af10a7$export$3f01106131746282;
var $0e727cd460af10a7$export$8893a52c4c1a74dc;
var $0e727cd460af10a7$export$1b246d2f2efdafde;
var $0e727cd460af10a7$export$95c4b71b6433cd9b;
var $0e727cd460af10a7$export$a491843cc088839f;
var $0e727cd460af10a7$export$e99ebfc19ac06f62;
var $0e727cd460af10a7$export$50e56048083c79d4;
var $0e727cd460af10a7$export$6a339dc159e3a2af;
var $0e727cd460af10a7$export$9f2360ce38e60765;
var $0e727cd460af10a7$export$c5f401355b5bd564;
var $0e727cd460af10a7$export$da544d36ec663620;
var $30eea9beccea1ad9$exports = {};


const $30eea9beccea1ad9$var$tourSchema = new $8dMYy$mongoose.Schema({
    name: {
        type: String,
        required: [
            true,
            "A tour must have a name"
        ],
        unique: true,
        minLength: [
            10,
            "A tour name must be more than or equal to 10 characters", 
        ],
        maxLength: [
            40,
            "A tour name must be smaller or equal to 40 characters"
        ]
    },
    ratingsAverage: {
        type: Number,
        default: 4.5,
        min: [
            1,
            "A tour ratingsAverage should be bigger than or equal to 1"
        ],
        max: [
            5,
            "A tour ratingsAverage should be smaller than or equal to 5"
        ]
    },
    ratingsQuantity: {
        type: Number
    },
    slug: {
        type: String
    },
    secretTour: {
        type: Boolean,
        default: false
    },
    price: {
        type: Number,
        required: [
            true,
            "A tour must have price"
        ]
    },
    priceDiscount: {
        type: Number,
        validate: {
            validator: function(val) {
                return val < this.price;
            },
            message: "Price Discount: [{VALUE}] should be smaller than regular price"
        }
    },
    difficulty: {
        type: String,
        enum: {
            values: [
                "easy",
                "difficult",
                "medium"
            ],
            message: "Difficulty must be either easy, difficult or medium"
        }
    },
    duration: {
        required: [
            true,
            "A tour must have a duration"
        ],
        type: Number
    },
    summary: {
        type: String,
        required: [
            true,
            "A tour must have a summary"
        ]
    },
    description: {
        type: String
    },
    maxGroupSize: {
        type: Number
    },
    createdAt: {
        type: Date,
        default: Date.now()
    },
    startDates: [
        Date
    ],
    imageCover: {
        type: String,
        required: [
            true,
            "A tour must have a imageCover"
        ]
    },
    images: [
        String
    ],
    startLocation: {
        type: {
            type: String,
            enum: {
                values: [
                    "Point"
                ],
                message: "Start location type can only be Point"
            }
        },
        coordinates: [
            Number
        ],
        description: String,
        address: String
    },
    locations: [
        {
            description: String,
            type: {
                type: String,
                enum: {
                    values: [
                        "Point"
                    ],
                    message: "Start location type can only be Point"
                }
            },
            coordinates: [
                Number
            ],
            day: Number
        }, 
    ],
    guides: [
        {
            type: $8dMYy$mongoose.Schema.ObjectId,
            ref: "User"
        }, 
    ]
}, {
    toJSON: {
        virtuals: true
    },
    toObject: {
        virtuals: true
    }
});
$30eea9beccea1ad9$var$tourSchema.index({
    price: 1,
    ratingsAverage: -1
});
$30eea9beccea1ad9$var$tourSchema.index({
    slug: 1
});
$30eea9beccea1ad9$var$tourSchema.index({
    startLocation: "2dsphere"
});
$30eea9beccea1ad9$var$tourSchema.virtual("durationWeeks").get(function() {
    return this.duration / 7;
});
$30eea9beccea1ad9$var$tourSchema.virtual("reviews", {
    ref: "Review",
    foreignField: "tour",
    localField: "_id"
});
$30eea9beccea1ad9$var$tourSchema.pre("save", function(next) {
    this.slug = $8dMYy$slugify(this.name, {
        lower: true
    });
    next();
});
// tourSchema.post("save", function(doc, next) {
//   console.log(doc);
//   next();
// })
$30eea9beccea1ad9$var$tourSchema.pre(/^find/, function(next) {
    this.find({
        secretTour: {
            $ne: true
        }
    });
    next();
});
$30eea9beccea1ad9$var$tourSchema.pre(/^find/, function(next) {
    this.populate({
        path: "guides",
        select: "-__v -passwordChangedAt"
    });
    next();
});
const $30eea9beccea1ad9$var$Tour = $8dMYy$mongoose.model("Tour", $30eea9beccea1ad9$var$tourSchema);
$30eea9beccea1ad9$exports = $30eea9beccea1ad9$var$Tour;


var $37cb8f63f6cdb43b$exports = {};
class $37cb8f63f6cdb43b$var$APIFeatures {
    filter() {
        // Create query object
        const excludeQuery = [
            "limit",
            "sort",
            "fields",
            "page"
        ];
        let queryObj = {
            ...this.queryString
        };
        excludeQuery.forEach((ele)=>delete queryObj[ele]
        );
        // Creating query String
        const queryStr = JSON.stringify(queryObj).replace(/\b(gte|gt|lte|lt)\b/g, (ele)=>`$${ele}`
        );
        this.query = this.query.find(JSON.parse(queryStr));
        return this;
    }
    sort() {
        if (this.queryString.sort) {
            const sortBy = this.queryString.sort.split(",").join(" ");
            this.query = this.query.sort(sortBy);
        } else this.query = this.query.sort("-createdAt");
        return this;
    }
    limitFields() {
        if (this.queryString.fields) {
            const fields = this.queryString.fields.split(",").join(" ");
            this.query = this.query.select(fields);
        } else this.query = this.query.select("-__v");
        return this;
    }
    paginate() {
        const page = this.queryString.page * 1 || 1;
        const limit = this.queryString.limit * 1 || 100;
        const skip = (page - 1) * limit;
        this.query = this.query.skip(skip).limit(limit);
        return this;
    }
    constructor(query, queryString){
        this.query = query;
        this.queryString = queryString;
    }
}
$37cb8f63f6cdb43b$exports = $37cb8f63f6cdb43b$var$APIFeatures;


var $545b77630906f886$exports = {};
$545b77630906f886$exports = (func)=>{
    return (req, res, next)=>{
        func(req, res, next).catch((err)=>next(err)
        );
    };
};


var $d91720fab1a79345$exports = {};
class $d91720fab1a79345$var$AppError extends Error {
    constructor(message, statusCode){
        super(message);
        this.statusCode = statusCode;
        this.status = `${statusCode}`.startsWith("4") ? "fail" : "error";
        this.isTrusted = true;
        Error.captureStackTrace(this, this.constructor);
    }
}
$d91720fab1a79345$exports = $d91720fab1a79345$var$AppError;


var $2bdce3b0def30d28$export$36a479340da3c347;
var $2bdce3b0def30d28$export$3220ead45e537228;
var $2bdce3b0def30d28$export$5d49599920443c31;
var $2bdce3b0def30d28$export$2eb5ba9a66e42816;
var $2bdce3b0def30d28$export$2774c37398bee8b2;



$2bdce3b0def30d28$export$36a479340da3c347 = (Model)=>$545b77630906f886$exports(async (req, res, next)=>{
        const doc = await Model.findByIdAndDelete(req.params.id);
        if (!doc) return next(new $d91720fab1a79345$exports(`Can't find that document`, 404));
        res.status(204).json({
            status: "success",
            data: null
        });
    })
;
$2bdce3b0def30d28$export$3220ead45e537228 = (Model)=>$545b77630906f886$exports(async (req, res, next)=>{
        const doc = await Model.findByIdAndUpdate(req.params.id, req.body, {
            new: true,
            runValidators: true
        });
        if (!doc) return next(new $d91720fab1a79345$exports(`Can't find document with ${req.params.id}!`, 404));
        res.status(200).json({
            status: "success",
            data: {
                ...doc._doc
            }
        });
    })
;
$2bdce3b0def30d28$export$5d49599920443c31 = (Model)=>$545b77630906f886$exports(async (req, res, next)=>{
        const doc = await Model.create(req.body);
        res.status(201).json({
            status: "success",
            data: {
                ...doc._doc
            }
        });
    })
;
$2bdce3b0def30d28$export$2eb5ba9a66e42816 = (Model)=>$545b77630906f886$exports(async (req, res, next)=>{
        const doc = await Model.findById(req.params.id).populate({
            path: "reviews"
        });
        if (!doc) return next(new $d91720fab1a79345$exports(`Can't find document with ${req.params.id}!`, 404));
        if (doc.$$populatedVirtuals) doc.reviews = doc.$$populatedVirtuals.reviews;
        res.status(200).json({
            status: "success",
            data: {
                doc: doc
            }
        });
    })
;
$2bdce3b0def30d28$export$2774c37398bee8b2 = (Model)=>$545b77630906f886$exports(async (req, res, next)=>{
        const filter = req.params.tourId ? {
            tour: req.params.tourId
        } : {
        };
        // Api Features
        const features = new $37cb8f63f6cdb43b$exports(Model.find(filter), req.query).filter().sort().limitFields().paginate();
        // Executing Query
        const doc = await features.query;
        res.status(200).json({
            status: "success",
            results: doc.length,
            data: {
                doc: doc
            }
        });
    })
;




// const multerStorage = multer.diskStorage({
//   destination: (req, file, cb) => {
//     cb(null, `public/img/users`);
//   },
//   filename: (req, file, cb) => {
//     cb(null, `user-${req.user._id}-${Date.now()}.jpeg`);
//   },
// });
var $da4dd627b52a82a0$export$9dd6c93f72886ac9;
var $da4dd627b52a82a0$export$bff4f91618df0983;

$da4dd627b52a82a0$export$9dd6c93f72886ac9 = $8dMYy$multer.memoryStorage();
$da4dd627b52a82a0$export$bff4f91618df0983 = (req, file, cb)=>{
    if (file.mimetype.startsWith("image")) cb(null, true);
    else cb(new AppError(`Provided file is not an image. Please provide an image file`), false);
};


var $0e727cd460af10a7$require$multerStorage = $da4dd627b52a82a0$export$9dd6c93f72886ac9;
var $0e727cd460af10a7$require$multerFilter = $da4dd627b52a82a0$export$bff4f91618df0983;
const $0e727cd460af10a7$var$upload = $8dMYy$multer({
    storage: $0e727cd460af10a7$require$multerStorage,
    filter: $0e727cd460af10a7$require$multerFilter
});
$0e727cd460af10a7$export$b4cc9a7f549f80be = $0e727cd460af10a7$var$upload.fields([
    {
        name: "imageCover",
        maxCount: 1
    },
    {
        name: "images",
        maxCount: 5
    }, 
]);
$0e727cd460af10a7$export$3f01106131746282 = $545b77630906f886$exports(async (req, res, next)=>{
    req.body.imageCover = `tour-${req.params.id}-${Date.now()}.jpeg`;
    req.body.images = [];
    await $8dMYy$sharp(req.files.imageCover[0].buffer).resize(2000, 1333).toFormat("jpeg").jpeg({
        quality: 90
    }).toFile(`public/img/tours/${req.body.imageCover}`);
    await Promise.all(req.files.images.map(async (file, index)=>{
        const filename = `tour-${req.params.id}-${Date.now()}-${index + 1}.jpeg`;
        req.body.images.push(filename);
        return await $8dMYy$sharp(file.buffer).resize(2000, 1333).toFormat("jpeg").jpeg({
            quality: 90
        }).toFile(`public/img/tours/${filename}`);
    }));
    next();
});
$0e727cd460af10a7$export$8893a52c4c1a74dc = (req, res, next)=>{
    req.query.limit = "5";
    req.query.sort = "-ratingsAverage,price";
    next();
};
$0e727cd460af10a7$export$1b246d2f2efdafde = $2bdce3b0def30d28$export$2774c37398bee8b2($30eea9beccea1ad9$exports);
$0e727cd460af10a7$export$95c4b71b6433cd9b = $2bdce3b0def30d28$export$2eb5ba9a66e42816($30eea9beccea1ad9$exports);
$0e727cd460af10a7$export$a491843cc088839f = $2bdce3b0def30d28$export$5d49599920443c31($30eea9beccea1ad9$exports);
$0e727cd460af10a7$export$e99ebfc19ac06f62 = $2bdce3b0def30d28$export$3220ead45e537228($30eea9beccea1ad9$exports);
$0e727cd460af10a7$export$50e56048083c79d4 = $2bdce3b0def30d28$export$36a479340da3c347($30eea9beccea1ad9$exports);
$0e727cd460af10a7$export$6a339dc159e3a2af = $545b77630906f886$exports(async (req, res, next)=>{
    const stats = await $30eea9beccea1ad9$exports.aggregate([
        {
            $match: {
                ratingsAverage: {
                    $gte: 4.5
                }
            }
        },
        {
            $group: {
                _id: "$difficulty",
                numTours: {
                    $sum: 1
                },
                numRatings: {
                    $sum: "$ratingsQuantity"
                },
                avgRating: {
                    $avg: "$ratingsAverage"
                },
                avgPrice: {
                    $avg: "$price"
                },
                minPrice: {
                    $min: "$price"
                },
                maxPrice: {
                    $max: "$price"
                }
            }
        },
        {
            $sort: {
                avgRating: -1
            }
        }, 
    ]);
    res.status(200).json({
        status: "success",
        data: {
            stats: stats
        }
    });
});
$0e727cd460af10a7$export$9f2360ce38e60765 = $545b77630906f886$exports(async (req, res, next)=>{
    const year = req.params.year;
    const plan = await $30eea9beccea1ad9$exports.aggregate([
        {
            $unwind: "$startDates"
        },
        {
            $match: {
                startDates: {
                    $gte: new Date(`${year}-01-01`),
                    $lte: new Date(`${year}-12-31`)
                }
            }
        },
        {
            $group: {
                _id: {
                    $month: "$startDates"
                },
                numTourStart: {
                    $sum: 1
                },
                tours: {
                    $push: "$name"
                }
            }
        },
        {
            $addFields: {
                month: "$_id"
            }
        },
        {
            $sort: {
                numTourStart: -1
            }
        },
        {
            $project: {
                _id: 0
            }
        }, 
    ]);
    res.status(200).json({
        status: "success",
        data: {
            plan: plan
        }
    });
});
$0e727cd460af10a7$export$c5f401355b5bd564 = $545b77630906f886$exports(async (req, res, next)=>{
    const { distance: distance , latlng: latlng  } = req.params;
    const unit = req.params.unit || "mi";
    const [lat, lng] = latlng.split(",");
    const radian = unit === "mi" ? distance / 3963.2 : distance / 6378.1;
    if (!distance) return next(new $d91720fab1a79345$exports(`Please provide the distance within the tours`), 400);
    if (!lat || !lng) return next(new $d91720fab1a79345$exports(`Latitude and longitute must be provided in the lat,lng format`), 400);
    const tours = await $30eea9beccea1ad9$exports.find({
        startLocation: {
            $geoWithin: {
                $centerSphere: [
                    [
                        lng,
                        lat
                    ],
                    radian
                ]
            }
        }
    });
    res.status(200).json({
        status: "success",
        results: tours.length,
        tours: tours
    });
});
$0e727cd460af10a7$export$da544d36ec663620 = $545b77630906f886$exports(async (req, res, next)=>{
    const { latlng: latlng  } = req.params;
    const unit = req.params.unit || "mi";
    const [lat, lng] = latlng.split(",");
    const multiplier = unit === "mi" ? 0.000621371 : 0.001;
    if (!lat || !lng) return next(new $d91720fab1a79345$exports(`Latitude and longitute must be provided in the lat,lng format`), 400);
    const distances = await $30eea9beccea1ad9$exports.aggregate([
        {
            $geoNear: {
                near: {
                    type: "Point",
                    coordinates: [
                        lng * 1,
                        lat * 1
                    ]
                },
                distanceField: "distance",
                distanceMultiplier: multiplier
            }
        },
        {
            $project: {
                distance: 1,
                name: 1
            }
        }, 
    ]);
    res.status(200).json({
        status: "success",
        results: distances.length,
        distances: distances
    });
});


var $6834832037f5000c$export$7200a869094fec36;
var $6834832037f5000c$export$596d806903d1f59e;
var $6834832037f5000c$export$eda7ca9e36571553;
var $6834832037f5000c$export$36c5658740f915be;
var $6834832037f5000c$export$66791fb2cfeec3e;
var $6834832037f5000c$export$dc726c8e334dd814;
var $6834832037f5000c$export$e2853351e15b7895;
// Review can only delete or editted by the creator
var $6834832037f5000c$export$3d018c011d828f0c;

var $4d30bd268cebc2d2$exports = {};




const $4d30bd268cebc2d2$var$userSchema = new $8dMYy$mongoose.Schema({
    name: {
        type: String,
        required: [
            true,
            "A user must have a name"
        ]
    },
    email: {
        type: String,
        required: [
            true,
            "A user must have an email"
        ],
        unique: true,
        validate: {
            validator: function(val) {
                return $8dMYy$validator.isEmail(val);
            },
            message: "Invalid email"
        }
    },
    password: {
        type: String,
        required: [
            true,
            "A user must have a password"
        ],
        minLength: [
            7,
            "Password must be at least 7 characters"
        ],
        maxLength: [
            16,
            "Password must not exceed 16 characters"
        ],
        select: false
    },
    confirmPassword: {
        type: String,
        required: [
            true,
            "A user must confirm his password"
        ],
        validate: {
            validator: function(val) {
                return this.password === val;
            },
            message: "Password didn't match"
        }
    },
    photo: {
        type: String,
        default: "default.jpg"
    },
    role: {
        type: String,
        enum: [
            "user",
            "admin",
            "guide",
            "lead-guide"
        ],
        default: "user"
    },
    passwordChangedAt: Date,
    passwordChangeToken: String,
    passwordChangeTokenExpiresIn: Date,
    active: {
        default: true,
        type: Boolean,
        select: false
    }
});
$4d30bd268cebc2d2$var$userSchema.pre("save", async function(next) {
    if (!this.isModified("password")) return next();
    this.password = await $8dMYy$bcryptjs.hash(this.password, 12);
    this.confirmPassword = undefined;
});
$4d30bd268cebc2d2$var$userSchema.pre("save", function(next) {
    if (!this.isModified("password") || this.isNew) return next();
    this.passwordChangedAt = Date.now() - 1000;
    next();
});
$4d30bd268cebc2d2$var$userSchema.pre(/^find/, function(next) {
    this.find({
        active: {
            $ne: false
        }
    });
    next();
});
// Instance Method available on all user documents
$4d30bd268cebc2d2$var$userSchema.methods.correctPassword = async function(decodedPassword, encodedPassword) {
    return await $8dMYy$bcryptjs.compare(decodedPassword, encodedPassword);
};
$4d30bd268cebc2d2$var$userSchema.methods.changedPasswordAfter = function(tokenIssuedAt) {
    if (this.passwordChangedAt) {
        const newPasswordChangedAt = parseInt(this.passwordChangedAt.getTime() / 1000, 10);
        return tokenIssuedAt > newPasswordChangedAt;
    }
    return false;
};
$4d30bd268cebc2d2$var$userSchema.methods.generateToken = function() {
    const resetToken = $8dMYy$crypto.randomBytes(32).toString("hex");
    this.passwordChangeToken = $8dMYy$crypto.createHash("sha256").update(resetToken).digest("hex");
    this.passwordChangeTokenExpiresIn = Date.now() + 600000;
    return resetToken;
};
const $4d30bd268cebc2d2$var$userModel = $8dMYy$mongoose.model("User", $4d30bd268cebc2d2$var$userSchema);
$4d30bd268cebc2d2$exports = $4d30bd268cebc2d2$var$userModel;






var $6834832037f5000c$require$promisify = $8dMYy$util.promisify;
var $14c6891082d8f12d$exports = {};

$14c6891082d8f12d$exports = class Email {
    newTransport() {
        //sending email via sendGrid
        return $8dMYy$nodemailer.createTransport({
            service: "SendGrid",
            auth: {
                user: process.env.SENDGRID_USERNAME,
                pass: process.env.SENDGRID_PASSWORD
            }
        });
    }
    async sendEmail(subject, message) {
        const htmlMessage = `<p>${message}</p>`;
        return await this.newTransport().sendMail({
            from: this.from,
            to: this.to,
            subject: subject,
            // text: message,
            html: htmlMessage
        });
    }
    async sendWelcome() {
        const message = `Hello ${this.firstName}, hope you enjoy surfing on our website.`;
        await this.sendEmail("Welcome to the Natours family :-)", message);
    }
    async sendResetEmail() {
        const message = `Forgot your password?<br/> Click <a href="${this.url}">here</a> to reset your password. If you didn't requested this email ignore this mail.`;
        await this.sendEmail("Reset your password for Natours", message);
    }
    constructor(user, url){
        this.to = user.email;
        this.firstName = user.name.split(" ")[0];
        this.url = url;
        this.from = `Arpan Bari <${process.env.EMAIL_FROM}>`;
    }
};


var $1c7c978e31e76c4c$exports = {};


const $1c7c978e31e76c4c$var$reviewSchema = $8dMYy$mongoose.Schema({
    review: {
        type: String,
        required: [
            true,
            "Review must have a review"
        ]
    },
    ratings: {
        type: Number,
        min: [
            1,
            "Review rating should be more or equal to 1"
        ],
        max: [
            5,
            "Review rating should be less or equal to 5"
        ],
        default: 4.5
    },
    createdAt: {
        type: Date,
        default: Date.now()
    },
    tour: {
        type: $8dMYy$mongoose.Schema.ObjectId,
        ref: "Tour",
        required: [
            true,
            "Review must have a tour"
        ]
    },
    user: {
        type: $8dMYy$mongoose.Schema.ObjectId,
        ref: "User",
        required: [
            true,
            "Review must have a user"
        ]
    }
}, {
    toJSON: {
        virtual: true
    },
    toObject: {
        virtual: true
    }
});
// Indexing and unique so that a user can only post 1 review on a single tour
$1c7c978e31e76c4c$var$reviewSchema.index({
    tour: 1,
    user: 1
}, {
    unique: true
});
// Query middleware to transform a query before it is executed
$1c7c978e31e76c4c$var$reviewSchema.pre(/^find/, function(next) {
    this.populate({
        path: "user",
        select: "name photo"
    });
    next();
});
$1c7c978e31e76c4c$var$reviewSchema.pre(/^findOneAnd/, async function(next) {
    this.r = await this.findOne();
    console.log(this.r);
    next();
});
$1c7c978e31e76c4c$var$reviewSchema.post(/^findOneAnd/, function() {
    this.r.constructor.calcAverageSumRatings(this.r.tour);
});
// static function
$1c7c978e31e76c4c$var$reviewSchema.statics.calcAverageSumRatings = async function(tourId) {
    const stats = await this.aggregate([
        {
            $match: {
                tour: tourId
            }
        },
        {
            $group: {
                _id: "$tour",
                nRatings: {
                    $sum: 1
                },
                avgRatings: {
                    $avg: "$ratings"
                }
            }
        }, 
    ]);
    console.log(stats);
    if (stats.length > 0) await $30eea9beccea1ad9$exports.findByIdAndUpdate(tourId, {
        ratingsAverage: stats[0].avgRatings,
        ratingsQuantity: stats[0].nRatings
    });
    else await $30eea9beccea1ad9$exports.findByIdAndUpdate(tourId, {
        ratingsAverage: 4.5,
        ratingsQuantity: 0
    });
};
// document middleware POST, updating the tour averageRatings and ratingsQuantity
$1c7c978e31e76c4c$var$reviewSchema.post("save", function() {
    // calling static function on reviewModel
    this.constructor.calcAverageSumRatings(this.tour);
});
const $1c7c978e31e76c4c$var$reviewModel = $8dMYy$mongoose.model("Review", $1c7c978e31e76c4c$var$reviewSchema);
$1c7c978e31e76c4c$exports = $1c7c978e31e76c4c$var$reviewModel;


const $6834832037f5000c$var$signToken = (id)=>{
    return $8dMYy$jsonwebtoken.sign({
        id: id
    }, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRES_IN
    });
};
const $6834832037f5000c$var$sendTokenCookie = (res, token)=>{
    const cookieOptions = {
        expires: new Date(Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 86400000),
        httpOnly: true
    };
    if (process.env.NODE_ENV == "production") cookieOptions.secure = true;
    res.cookie(`jwt`, token, cookieOptions);
};
$6834832037f5000c$export$7200a869094fec36 = $545b77630906f886$exports(async (req, res, next)=>{
    const user = await $4d30bd268cebc2d2$exports.create({
        name: req.body.name,
        email: req.body.email,
        password: req.body.password,
        confirmPassword: req.body.confirmPassword,
        photo: req.body.photo,
        role: req.body.role
    });
    const token = $6834832037f5000c$var$signToken(user._id);
    $6834832037f5000c$var$sendTokenCookie(res, token);
    res.status(201).json({
        status: "success",
        token: token,
        user: user
    });
});
$6834832037f5000c$export$596d806903d1f59e = $545b77630906f886$exports(async (req, res, next)=>{
    const { email: email , password: password  } = req.body;
    // 1) Check if the email or password exits
    if (!email || !password) return next(new $d91720fab1a79345$exports(`Please provide email and password`, 400));
    // 2) Check if the user exits
    const user = await $4d30bd268cebc2d2$exports.findOne({
        email: email
    }).select("+password");
    // 3) Check if the password is correct
    if (!user) return next(new $d91720fab1a79345$exports(`Invalid email or Password`, 401));
    else if (!await user.correctPassword(password, user.password)) return next(new $d91720fab1a79345$exports(`Invalid email or Password`, 401));
    // 4) Generate token
    const token = $6834832037f5000c$var$signToken(user._id);
    $6834832037f5000c$var$sendTokenCookie(res, token);
    // 5) Send the response
    res.status(200).json({
        status: "success",
        token: token
    });
});
$6834832037f5000c$export$eda7ca9e36571553 = $545b77630906f886$exports(async (req, res, next)=>{
    // 1) Check if token exits
    let token = req.headers.authorization;
    if (!token) return next(new $d91720fab1a79345$exports(`Please provide token in header`, 401));
    token = req.headers.authorization.split(" ")[1];
    // 2) Check if token is valid
    const data = await $6834832037f5000c$require$promisify($8dMYy$jsonwebtoken.verify)(token, process.env.JWT_SECRET);
    // 3) Check if user exists
    const user = await $4d30bd268cebc2d2$exports.findOne({
        _id: data.id
    });
    if (!user) return next(new $d91720fab1a79345$exports(`User didn't found. Please login again`, 401));
    // 4) Check if the password is unchanged
    if (user.changedPasswordAfter(data.iat)) return next(new $d91720fab1a79345$exports(`User has changed the password recently. Please login again`, 401));
    req.user = user;
    next();
});
$6834832037f5000c$export$36c5658740f915be = (...roles)=>{
    return (req, res, next)=>{
        if (!roles.includes(req.user.role)) return next(new $d91720fab1a79345$exports(`Can't perform this action for this user.`, 403));
        next();
    };
};
$6834832037f5000c$export$66791fb2cfeec3e = $545b77630906f886$exports(async (req, res, next)=>{
    // Check if the user with email exists
    const user = await $4d30bd268cebc2d2$exports.findOne({
        email: req.body.email
    });
    if (!user) return next(new $d91720fab1a79345$exports(`User with the provided email not found!`, 404));
    // Generate the token
    const resetToken = user.generateToken();
    user.save({
        validateBeforeSave: false
    });
    // Send email
    const resetURL = `${req.protocol}://${req.get("host")}/api/v1/users/resetPassword/${resetToken}`;
    try {
        await new $14c6891082d8f12d$exports(user, resetURL).sendResetEmail();
        // Send Response
        res.status(200).json({
            status: "success",
            message: "Token sent to email"
        });
    } catch (err) {
        user.passwordResetToken = undefined;
        user.passwordResetTokenExpiresIn = undefined;
        user.save({
            validateBeforeSave: false
        });
        return next(new $d91720fab1a79345$exports(`Couldn't send token to email`, 500));
    }
});
$6834832037f5000c$export$dc726c8e334dd814 = $545b77630906f886$exports(async (req, res, next)=>{
    // Check if the token is valid
    const hashedToken = $8dMYy$crypto.createHash("sha256").update(req.params.token).digest("hex");
    const user = await $4d30bd268cebc2d2$exports.findOne({
        passwordChangeToken: hashedToken,
        passwordChangeTokenExpiresIn: {
            $gt: Date.now()
        }
    });
    if (!user) return next(new $d91720fab1a79345$exports(`Invalid token or token is expired!`));
    // Change the password
    user.password = req.body.password;
    user.confirmPassword = req.body.confirmPassword;
    user.passwordChangeToken = undefined;
    user.passwordChangeTokenExpiresIn = undefined;
    await user.save();
    // Set the passwordChangedAt to current time in the pre middleware
    // Log the user in
    const token = $6834832037f5000c$var$signToken(user._id);
    $6834832037f5000c$var$sendTokenCookie(res, token);
    res.status(201).json({
        status: "success",
        token: token
    });
});
$6834832037f5000c$export$e2853351e15b7895 = $545b77630906f886$exports(async (req, res, next)=>{
    // Get the current user
    const user = await $4d30bd268cebc2d2$exports.findById(req.user._id).select("+password");
    if (!user) return next(new $d91720fab1a79345$exports(`User didn't found. Please login`, 401));
    // Check the current user password with the posted password
    if (!await user.correctPassword(req.body.currentPassword, user.password)) return next(new $d91720fab1a79345$exports(`Incorrect Password`, 401));
    // Update the password
    user.password = req.body.newPassword;
    user.confirmPassword = req.body.confirmNewPassword;
    await user.save();
    // Log the user in
    const token = $6834832037f5000c$var$signToken();
    $6834832037f5000c$var$sendTokenCookie(res, token);
    res.status(200).json({
        status: "success",
        token: token
    });
});
$6834832037f5000c$export$3d018c011d828f0c = async (req, res, next)=>{
    const loggedInUser = req.user._id;
    const review = await $1c7c978e31e76c4c$exports.findById(req.params.id);
    if (!review) return next(new $d91720fab1a79345$exports(`No review found!`, 404));
    if (`${loggedInUser}` !== `${review.user._id}`) return next(new $d91720fab1a79345$exports(`This review is not created by you. You can't edit or delete it.`, 401));
    next();
};


var $a4639b08bb0153a1$exports = {};
var $3e825aa3f0a0a768$export$308e5d29efcbb921;
var $3e825aa3f0a0a768$export$98596c466f7b9045;
var $3e825aa3f0a0a768$export$c3d3086f9027c35a;
var $3e825aa3f0a0a768$export$e42a3d813dd6123f;
var $3e825aa3f0a0a768$export$7019c694ef9e681d;
var $3e825aa3f0a0a768$export$189a68d831f3e4ec;


$3e825aa3f0a0a768$export$308e5d29efcbb921 = (req, res, next)=>{
    req.body.tour = req.body.tour || req.params.tourId;
    req.body.user = req.body.user || req.user._id;
    next();
};
$3e825aa3f0a0a768$export$98596c466f7b9045 = $2bdce3b0def30d28$export$2774c37398bee8b2($1c7c978e31e76c4c$exports);
$3e825aa3f0a0a768$export$c3d3086f9027c35a = $2bdce3b0def30d28$export$2eb5ba9a66e42816($1c7c978e31e76c4c$exports);
$3e825aa3f0a0a768$export$e42a3d813dd6123f = $2bdce3b0def30d28$export$5d49599920443c31($1c7c978e31e76c4c$exports);
$3e825aa3f0a0a768$export$7019c694ef9e681d = $2bdce3b0def30d28$export$3220ead45e537228($1c7c978e31e76c4c$exports);
$3e825aa3f0a0a768$export$189a68d831f3e4ec = $2bdce3b0def30d28$export$36a479340da3c347($1c7c978e31e76c4c$exports);




const $a4639b08bb0153a1$var$router = $8dMYy$express.Router({
    mergeParams: true
});
$a4639b08bb0153a1$var$router.route("/").get($3e825aa3f0a0a768$export$98596c466f7b9045).post($6834832037f5000c$export$eda7ca9e36571553, $6834832037f5000c$export$36c5658740f915be("user"), $3e825aa3f0a0a768$export$308e5d29efcbb921, $3e825aa3f0a0a768$export$e42a3d813dd6123f);
$a4639b08bb0153a1$var$router.route("/:id").get($3e825aa3f0a0a768$export$c3d3086f9027c35a).patch($6834832037f5000c$export$eda7ca9e36571553, $6834832037f5000c$export$36c5658740f915be("user"), $6834832037f5000c$export$3d018c011d828f0c, $3e825aa3f0a0a768$export$7019c694ef9e681d).delete($6834832037f5000c$export$eda7ca9e36571553, $6834832037f5000c$export$36c5658740f915be("user"), $6834832037f5000c$export$3d018c011d828f0c, $3e825aa3f0a0a768$export$189a68d831f3e4ec);
$a4639b08bb0153a1$exports = $a4639b08bb0153a1$var$router;


const $fea4391203025921$var$router = $8dMYy$express.Router();
// middleware: if there's router something like tours/dk9932/reviews -> review router will be called
$fea4391203025921$var$router.use("/:tourId/reviews", $a4639b08bb0153a1$exports);
$fea4391203025921$var$router.route("/top-5-tours").get($0e727cd460af10a7$export$8893a52c4c1a74dc, $0e727cd460af10a7$export$1b246d2f2efdafde);
$fea4391203025921$var$router.route("/toursWithin/:distance/center/:latlng/unit/:unit").get($0e727cd460af10a7$export$c5f401355b5bd564);
$fea4391203025921$var$router.route("/distance/center/:latlng/unit/:unit").get($0e727cd460af10a7$export$da544d36ec663620);
$fea4391203025921$var$router.route("/tour-stats").get($6834832037f5000c$export$eda7ca9e36571553, $6834832037f5000c$export$36c5658740f915be("admin", "lead-guide"), $0e727cd460af10a7$export$6a339dc159e3a2af);
$fea4391203025921$var$router.route("/monthly-plan/:year").get($6834832037f5000c$export$eda7ca9e36571553, $6834832037f5000c$export$36c5658740f915be("admin", "lead-guide"), $0e727cd460af10a7$export$9f2360ce38e60765);
$fea4391203025921$var$router.route("/").get($0e727cd460af10a7$export$1b246d2f2efdafde).post($6834832037f5000c$export$eda7ca9e36571553, $6834832037f5000c$export$36c5658740f915be("admin", "lead-guide"), $0e727cd460af10a7$export$b4cc9a7f549f80be, $0e727cd460af10a7$export$3f01106131746282, $0e727cd460af10a7$export$a491843cc088839f);
$fea4391203025921$var$router.route("/:id").get($0e727cd460af10a7$export$95c4b71b6433cd9b).patch($6834832037f5000c$export$eda7ca9e36571553, $6834832037f5000c$export$36c5658740f915be("admin", "lead-guide"), $0e727cd460af10a7$export$b4cc9a7f549f80be, $0e727cd460af10a7$export$3f01106131746282, $0e727cd460af10a7$export$e99ebfc19ac06f62).delete($6834832037f5000c$export$eda7ca9e36571553, $6834832037f5000c$export$36c5658740f915be("admin", "lead-guide"), $0e727cd460af10a7$export$50e56048083c79d4);
$fea4391203025921$exports = $fea4391203025921$var$router;


var $c1d90f64e015e9a9$exports = {};


var $01d6738f8a043c19$export$6dfd280b9fe74301;
var $01d6738f8a043c19$export$b1bc6476f6f39fb;
var $01d6738f8a043c19$export$f2268734e23d4931;
var $01d6738f8a043c19$export$e3ac7a5d19605772;
var $01d6738f8a043c19$export$7d0f10f273c0438a;
var $01d6738f8a043c19$export$dd7946daa6163e94;
var $01d6738f8a043c19$export$69093b9c569a5b5b;
var $01d6738f8a043c19$export$7cbf767827cd68ba;
var $01d6738f8a043c19$export$2084c7914edfe8de;







var $01d6738f8a043c19$require$multerStorage = $da4dd627b52a82a0$export$9dd6c93f72886ac9;
var $01d6738f8a043c19$require$multerFilter = $da4dd627b52a82a0$export$bff4f91618df0983;
const $01d6738f8a043c19$var$upload = $8dMYy$multer({
    storage: $01d6738f8a043c19$require$multerStorage,
    fileFilter: $01d6738f8a043c19$require$multerFilter
});
$01d6738f8a043c19$export$6dfd280b9fe74301 = $01d6738f8a043c19$var$upload.single("photo");
$01d6738f8a043c19$export$b1bc6476f6f39fb = $545b77630906f886$exports(async (req, res, next)=>{
    if (!req.file) return next();
    req.file.filename = `user-${req.user._id}-${Date.now()}.jpeg`;
    await $8dMYy$sharp(req.file.buffer).resize(500, 500).toFormat("jpeg").jpeg({
        quality: 90
    }).toFile(`public/img/users/${req.file.filename}`);
    next();
});
$01d6738f8a043c19$export$f2268734e23d4931 = (req, res, next)=>{
    // Throw error if the user tries to update password
    if (req.body.password || req.body.confirmPassword) return next(new $d91720fab1a79345$exports(`This route is not for updating password. Please use /update-my-password to update the same`, 400));
    next();
};
$01d6738f8a043c19$export$e3ac7a5d19605772 = $545b77630906f886$exports(async (req, res, next)=>{
    // Update the current user
    if (req.file) req.body.photo = req.file.filename;
    const tour = await $4d30bd268cebc2d2$exports.findByIdAndUpdate(req.user._id, req.body);
    res.status(200).json({
        status: "success",
        tour: {
            ...tour._doc
        }
    });
});
$01d6738f8a043c19$export$7d0f10f273c0438a = $545b77630906f886$exports(async (req, res)=>{
    // Change the user to inactive
    await $4d30bd268cebc2d2$exports.findByIdAndUpdate(req.user._id, {
        active: false
    });
    res.status(204).json({
        status: "success"
    });
});
$01d6738f8a043c19$export$dd7946daa6163e94 = (req, res, next)=>{
    req.params.id = req.user._id;
    next();
};
$01d6738f8a043c19$export$69093b9c569a5b5b = $2bdce3b0def30d28$export$2774c37398bee8b2($4d30bd268cebc2d2$exports);
$01d6738f8a043c19$export$7cbf767827cd68ba = $2bdce3b0def30d28$export$2eb5ba9a66e42816($4d30bd268cebc2d2$exports);
$01d6738f8a043c19$export$2084c7914edfe8de = $2bdce3b0def30d28$export$36a479340da3c347($4d30bd268cebc2d2$exports);


const $c1d90f64e015e9a9$var$router = $8dMYy$express.Router();
// Auth routes
$c1d90f64e015e9a9$var$router.route("/login").post($6834832037f5000c$export$596d806903d1f59e);
$c1d90f64e015e9a9$var$router.route("/sign-up").post($6834832037f5000c$export$7200a869094fec36);
$c1d90f64e015e9a9$var$router.route("/forgot-password").post($6834832037f5000c$export$66791fb2cfeec3e);
$c1d90f64e015e9a9$var$router.route("/reset-password/:token").patch($6834832037f5000c$export$dc726c8e334dd814);
$c1d90f64e015e9a9$var$router.route("/update-my-password").patch($6834832037f5000c$export$eda7ca9e36571553, $6834832037f5000c$export$e2853351e15b7895);
$c1d90f64e015e9a9$var$router.route("/update-my-details").patch($6834832037f5000c$export$eda7ca9e36571553, $01d6738f8a043c19$export$f2268734e23d4931, $01d6738f8a043c19$export$6dfd280b9fe74301, $01d6738f8a043c19$export$b1bc6476f6f39fb, $01d6738f8a043c19$export$e3ac7a5d19605772);
$c1d90f64e015e9a9$var$router.route("/me").get($6834832037f5000c$export$eda7ca9e36571553, $01d6738f8a043c19$export$dd7946daa6163e94, $01d6738f8a043c19$export$7cbf767827cd68ba);
$c1d90f64e015e9a9$var$router.route("/delete-me").delete($6834832037f5000c$export$eda7ca9e36571553, $01d6738f8a043c19$export$7d0f10f273c0438a);
$c1d90f64e015e9a9$var$router.route("/:id").get($6834832037f5000c$export$eda7ca9e36571553, $6834832037f5000c$export$36c5658740f915be("admin"), $01d6738f8a043c19$export$7cbf767827cd68ba).delete($6834832037f5000c$export$eda7ca9e36571553, $6834832037f5000c$export$36c5658740f915be("admin"), $01d6738f8a043c19$export$2084c7914edfe8de);
// User routes
$c1d90f64e015e9a9$var$router.route("/").get($01d6738f8a043c19$export$69093b9c569a5b5b);
$c1d90f64e015e9a9$exports = $c1d90f64e015e9a9$var$router;




var $7c7cfaaf5a44b79d$exports = {};

const $7c7cfaaf5a44b79d$var$handleCastError = (err)=>{
    const message = `Invalid ${err.path}: ${err.stringValue}`;
    return new $d91720fab1a79345$exports(message, 400);
};
const $7c7cfaaf5a44b79d$var$handleDuplicateKey = (err)=>{
    const message = `Duplicate ${err.keyValue}. Please try another one`;
    return new $d91720fab1a79345$exports(message, 400);
};
const $7c7cfaaf5a44b79d$var$handleValidationError = (err)=>{
    const message = Object.values(err.errors).map((el)=>el.message
    );
    return new $d91720fab1a79345$exports(message.join(". "), 400);
};
const $7c7cfaaf5a44b79d$var$handleTokenExpiredError = ()=>{
    return new $d91720fab1a79345$exports(`Token expired. Please login again.`, 401);
};
const $7c7cfaaf5a44b79d$var$handleJsonWebTokenError = ()=>{
    return new $d91720fab1a79345$exports(`Invalid token. Please login again.`, 401);
};
const $7c7cfaaf5a44b79d$var$errDev = (err, res)=>{
    res.status(err.statusCode).json({
        status: err.status,
        message: err.message,
        error: err,
        stack: err.stack
    });
};
const $7c7cfaaf5a44b79d$var$errProd = (err, res)=>{
    console.log(err.message);
    if (err.isTrusted) res.status(err.statusCode).json({
        status: err.status,
        message: err.message
    });
    else res.status(500).json({
        status: "error",
        message: "Something went very wrong!"
    });
};
$7c7cfaaf5a44b79d$exports = (err, req, res, next)=>{
    err.statusCode = err.statusCode || 500;
    err.status = err.status || "error";
    if (process.env.NODE_ENV === "development") $7c7cfaaf5a44b79d$var$errDev(err, res);
    else {
        let error = err;
        if (err.name === "CastError") error = $7c7cfaaf5a44b79d$var$handleCastError(error);
        if (err.code === 11000) error = $7c7cfaaf5a44b79d$var$handleDuplicateKey(error);
        if (err.name === "ValidationError") error = $7c7cfaaf5a44b79d$var$handleValidationError(error);
        if (err.name === "TokenExpiredError") error = $7c7cfaaf5a44b79d$var$handleTokenExpiredError();
        if (err.name === "JsonWebTokenError") error = $7c7cfaaf5a44b79d$var$handleJsonWebTokenError();
        $7c7cfaaf5a44b79d$var$errProd(error, res);
    }
    next();
};


// process.on("uncaughtException", () => {
//   console.log("Error! Shutting down....");
//   process.exit(1);
// });
const $23f37e54094919a0$var$app = $8dMYy$express();
// Parsing json into req.body
$23f37e54094919a0$var$app.use($8dMYy$express.json()); // middleware
// Testing middleware
$23f37e54094919a0$var$app.use((req, res, next)=>{
    req.requestedTime = new Date().toISOString();
    next();
});
const $23f37e54094919a0$var$limiter = $8dMYy$expressratelimit({
    max: 100,
    windowMs: 3600000,
    message: "Too many request. Please try again in an hour"
});
// Limiting request from 1 IP
$23f37e54094919a0$var$app.use("/api", $23f37e54094919a0$var$limiter);
// Sanitizing NoSQL Injection
$23f37e54094919a0$var$app.use($8dMYy$expressmongosanitize());
// Sanitizing Cross
$23f37e54094919a0$var$app.use($8dMYy$xssclean());
// Preventing parameter pollution
$23f37e54094919a0$var$app.use($8dMYy$hpp({
    whitelist: [
        "ratingsAverage",
        "ratingsQuantity",
        "duration",
        "maxGroupSize",
        "difficulty",
        "price", 
    ]
}));
$8dMYy$dotenv.config({
    path: "./config.env"
});
const $23f37e54094919a0$var$DB = process.env.DATABASE.replace("<password>", process.env.DATABASE_PASSWORD);
$8dMYy$mongoose.connect($23f37e54094919a0$var$DB, {
    useNewUrlParser: true,
    useCreateIndex: true,
    useFindAndModify: false
}).then(()=>console.log("Database connect successfully")
);
const $23f37e54094919a0$var$port = 3000;
$23f37e54094919a0$var$app.use("/api/v1/tours", $fea4391203025921$exports);
$23f37e54094919a0$var$app.use("/api/v1/users", $c1d90f64e015e9a9$exports);
$23f37e54094919a0$var$app.use("/api/v1/reviews", $a4639b08bb0153a1$exports);
$23f37e54094919a0$var$app.all("*", (req, res, next)=>{
    const err = new $d91720fab1a79345$exports(`Can't find ${req.originalUrl} route!`, 404);
    next(err);
});
$23f37e54094919a0$var$app.use($7c7cfaaf5a44b79d$exports);
const $23f37e54094919a0$var$server = $23f37e54094919a0$var$app.listen($23f37e54094919a0$var$port, ()=>{
    console.log(`Listening to the requests at port ${$23f37e54094919a0$var$port}`);
}); // process.on("unhandledRejection", () => {
 //   console.log("Error! Shutting down....");
 //   server.close(() => {
 //     process.exit(1);
 //   });
 // });


//# sourceMappingURL=bundle.js.map
