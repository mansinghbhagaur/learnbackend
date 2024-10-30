import mongoose from "mongoose";
import { User } from "../models/user.model.js";
import { ApiError } from "../utils/ApiError.js";
import ApiResponse from "../utils/ApiResponse.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import uploadOnCloudinary from "../utils/cloudinary.js";
import jwt from "jsonwebtoken";
import { v2 as cloudinary } from "cloudinary";
import fs from "fs";

const generateAccessAndRefreshToken = async (userId) => {
  try {
    const user = await User.findById(userId);
    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();

    // adding user refresh token
    user.refreshToken = refreshToken;
    await user.save({ validateBeforeSave: false });

    // access token
    return { accessToken, refreshToken };
  } catch (error) {
    throw new ApiError(
      500,
      "Something went wrong while generating refresh and access token"
    );
  }
};

const registerUser = asyncHandler(async (req, res) => {
  //   res.status(200).json({
  //     message: "ok",
  //   });
  // get user details from frontend
  const { username, fullname, email, password } = req.body;
  //   console.log("email: ", email);

  //   validation - not empty

  if (
    [username, fullname, email, password].some((field) => field?.trim === "")
  ) {
    throw new ApiError("400", "All fields are required");
  }

  // check if user already exists: username, email

  const existedUser = await User.findOne({
    $or: [{ username }, { email }],
  });

  //   check exist user

  if (existedUser) {
    throw new ApiError(409, "User with email or username already exists");
  }

  // check for image, check for avatar

  const avatarLocalPath = req.files?.avatar[0]?.path;
  //   const coverImageLocalPath = req.files?.coverImage[0]?.path;
  let coverImageLocalPath;
  if (
    req.files &&
    Array.isArray(req.files.coverImage) &&
    req.files.coverImage.length > 0
  ) {
    coverImageLocalPath = req.files.coverImage[0].path;
  }

  if (!avatarLocalPath) {
    throw new ApiError(400, "Avatar file is required");
  }

  // upload them to cloudinary, avatar

  const avatar = await uploadOnCloudinary(avatarLocalPath);
  const coverImage = await uploadOnCloudinary(coverImageLocalPath);

  // check avatar

  if (!avatar) {
    throw new ApiError(400, "Avatar file is required");
  }

  // create user object - create entry in db

  const user = await User.create({
    fullname,
    avatar: avatar.url,
    coverImage: coverImage?.url || "",
    password,
    email,
    username: username.toLowerCase(),
  });

  // remove password and refresh token field from response
  const createdUser = await User.findById(user._id).select(
    "-password -refreshToken"
  );
  // check for user creation
  if (!createdUser) {
    throw new ApiError(500, "something went wrong while registering the user");
  }

  // return response

  return res
    .status(201)
    .json(new ApiResponse(200, createdUser, "User registered Successfully"));
});

const loginUser = asyncHandler(async (req, res) => {
  // req boy -> data
  const { email, username, password } = req.body;
  // username or email
  if (!(username || email)) {
    throw new ApiError(400, "username or email is required");
  }
  // find the user
  const user = await User.findOne({
    $or: [{ username }, { email }],
  });

  // user check register not or
  if (!user) {
    throw new ApiError(404, "user does not exist");
  }

  // password check
  const isPasswordValid = await user.isPasswordCorrect(password);

  // check user password if condition
  if (!isPasswordValid) {
    throw new ApiError(401, "invalid user credentials");
  }

  // generate refresh token and accesstoken
  const { refreshToken, accessToken } = await generateAccessAndRefreshToken(
    user._id
  );

  // send cookie
  const loggedInUser = await User.findById(user._id).select(
    "-password -refreshToken"
  );

  const options = {
    httpOnly: true,
    secure: true,
  };

  return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
      new ApiResponse(
        200,
        { user: loggedInUser, accessToken, refreshToken },
        "user logged in successfully"
      )
    );
});

// logout user
const logoutUser = asyncHandler(async (req, res) => {
  await User.findByIdAndUpdate(
    req.user._id,
    {
      $unset: { refreshToken: 1 },
    },
    {
      new: true,
    }
  );
  const options = {
    httpOnly: true,
    secure: true,
  };

  return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "User logged Out"));
});

const refreshAccessToken = asyncHandler(async (req, res) => {
  const incomingRefreshToken =
    req.cookies.refreshToken || req.body.refreshToken;

  if (!incomingRefreshToken) {
    throw new ApiError(401, "Unauthorization request");
  }

  try {
    const decodedToken = jwt.verify(
      incomingRefreshToken,
      process.env.REFRESH_TOKEN_SECRET
    );

    const user = await User.findById(decodedToken?._id);

    if (!user) {
      throw new ApiError(401, "Invalid refresh Token");
    }

    if (incomingRefreshToken !== user?.refreshToken) {
      throw new ApiError(401, "Refresh token is expired or used");
    }

    const options = {
      httpOnly: true,
      secure: true,
    };

    const { accessToken, newRefreshToken } =
      await generateAccessAndRefreshToken(user._id);

    return res
      .status(200)
      .cookie("accessToken", accessToken, options)
      .cookie("refreshToken", newRefreshToken, options)
      .json(
        new ApiResponse(
          200,
          { accessToken, refreshToken: newRefreshToken },
          "Access Token refreshed"
        )
      );
  } catch (error) {
    throw new ApiError(401, error?.message || "Invalid refresh token");
  }
});

// change current password

const changeCurrentPassword = asyncHandler(async (req, res) => {
  const { oldPassword, newPassword } = req.body;

  const user = await User.findById(req.user?._id);

  const isPasswordCorrects = await user.isPasswordCorrect(oldPassword);

  if (!isPasswordCorrects) {
    throw new ApiError(400, "Invalid old password");
  }

  user.password = newPassword;
  await user.save({ validateBeforeSave: false });

  return res.status(200).json(new ApiResponse(200, {}, "Password changed "));
});

const getCurrentUser = asyncHandler(async (req, res) => {
  return res
    .status(200)
    .json(new ApiResponse(200, req.user, "User Fetched Successfully"));
});

const updateAccountDetails = asyncHandler(async (req, res) => {
  const { fullname, email } = req.body;

  if (!(fullname || email)) {
    throw new ApiError(400, "all fields are required");
  }

  const user = await User.findByIdAndUpdate(
    req.user._id,
    {
      $set: { fullname, email: email },
    },
    { new: true }
  ).select("-password");

  return res
    .status(200)
    .json(new ApiResponse(200, user, "Account details updated successfully"));
});

// update avatar user

// const updateUserAvatar = asyncHandler(async (req, res) => {
//   const avatarLocalPath = req.file?.path;

//   if (!avatarLocalPath) {
//     throw new ApiError(400, "Avatar file is missing");
//   }

//   const avatar = await uploadOnCloudinary(avatarLocalPath);

//   if (!avatar.url) {
//     throw new ApiError(400, "Error while uploading on avatar");
//   }

//   const user = await User.findByIdAndUpdate(
//     req.user?._id,
//     {
//       $set: {
//         avatar: avatar.url,
//       },
//     },
//     { new: true }
//   ).select("-password");

//   // res send
//   return res
//     .status(200)
//     .json(new ApiResponse(200, user, "Avatar Image updated Successfully"));
// });

const updateUserAvatar = asyncHandler(async (req, res) => {
  const avatarLocalPath = req.file?.path;

  if (!avatarLocalPath) {
    throw new ApiError(400, "Avatar file is missing");
  }

  // Find the user
  const user = await User.findById(req.user?._id).select("avatar");

  if (!user) {
    throw new ApiError(404, "User not found");
  }

  // If the user has an existing avatar, delete it from Cloudinary
  const oldAvatarPublicId = user.avatar.split("/").pop().split(".")[0]; // Assuming the avatar URL format includes the public ID

  if (user.avatar) {
    await cloudinary.uploader.destroy(oldAvatarPublicId); // Remove the old avatar
  }

  // Upload the new avatar
  let avatar;
  try {
    avatar = await uploadOnCloudinary(avatarLocalPath);
  } catch (error) {
    console.error("Upload error:", error);
  }

  if (!avatar || !avatar.url) {
    // Attempt to unlink the file only if it exists
    try {
      await fs.access(avatarLocalPath); // Check if the file exists
      await fs.unlink(avatarLocalPath); // Remove the local file
    } catch (err) {
      console.error("Error deleting local file:", err);
    }

    throw new ApiError(400, "Error while uploading the avatar");
  }

  // Update user with new avatar URL
  await User.findByIdAndUpdate(
    req.user?._id,
    {
      $set: {
        avatar: avatar.url,
      },
    },
    { new: true }
  ).select("-password");

  // Response
  return res
    .status(200)
    .json(new ApiResponse(200, user, "Avatar image updated successfully"));
});

// update cover image user

const updateUserCoverImage = asyncHandler(async (req, res) => {
  const coverImageLocalPath = req.file?.path;

  if (!coverImageLocalPath) {
    throw new ApiError(400, "Cover Image file is missing");
  }

  const coverImage = await uploadOnCloudinary(coverImageLocalPath);

  if (!coverImage.url) {
    throw new ApiError(400, "Error while uploading on Cover Image");
  }

  const user = await User.findByIdAndUpdate(
    req.user?._id,
    {
      $set: {
        coverImage: coverImage.url,
      },
    },
    { new: true }
  ).select("-password");

  // res send
  return res
    .status(200)
    .json(new ApiResponse(200, user, "Cover Image updated Successfully"));
});

// ---------------------------------------------------------------------------------------------
// Get User channel profile or subscription  aggregate piplines
// ---------------------------------------------------------------------------------------------

// const getUserChannelProfile = await asyncHandler(async (req, res) => {
//   const { username } = req.params;
//   // check username
//   if (!username?.trim) {
//     throw new ApiError(400, "username missing");
//   }

//   // aggregate pipeline match user
//   const channel = await User.aggregate([
//     {
//       $match: {
//         username: username?.toLowerCase(),
//       },
//     },
//     {
//       $lookup: {
//         from: "subscriptions",
//         localField: "_id",
//         foreignField: "channel",
//         as: "subscribers",
//       },
//     },
//     {
//       $lookup: {
//         from: "subscriptions",
//         localField: "_id",
//         foreignField: "subscriber",
//         as: "subscribedTo",
//       },
//     },
//     {
//       $addFields: {
//         subcribersCount: {
//           $size: "$subscribers",
//         },
//         channelsSubscribedCount: {
//           $size: "subscribedTo",
//         },
//         isSubscribed: {
//           $cond: {
//             if: { $in: [req.user?._id, "$subscribers.subscriber"] },
//             then: true,
//             else: false,
//           },
//         },
//       },
//     },
//     {
//       $project: {
//         fullname: 1,
//         username: 1,
//         subcribersCount: 1,
//         channelsSubscribedCount: 1,
//         isSubscribed: 1,
//         avatar: 1,
//         coverImage: 1,
//         email: 1,
//       },
//     },
//   ]);

//   // check channel
//   if (!channel?.length) {
//     throw new ApiError(404, "Channel does not exits");
//   }

//   // return get channel send response
//   return res
//     .status(200)
//     .json(
//       new ApiResponse(200, channel[0], "User channel fetched successfully")
//     );
// });

const getUserChannelProfile = await asyncHandler(async (req, res) => {
  const { username } = req.params;

  // यूज़रनेम की जांच करें
  if (!username || !username.trim()) {
    throw new ApiError(400, "यूज़रनेम गायब है");
  }

  // एग्रीगेशन पाइपलाइन से उपयोगकर्ता को मिलाएँ
  const channel = await User.aggregate([
    {
      $match: {
        username: username.toLowerCase(),
      },
    },
    {
      $lookup: {
        from: "subscriptions",
        localField: "_id",
        foreignField: "channel",
        as: "subscribers",
      },
    },
    {
      $lookup: {
        from: "subscriptions",
        localField: "_id",
        foreignField: "subscriber",
        as: "subscribedTo",
      },
    },
    {
      $addFields: {
        subscribersCount: {
          $size: "$subscribers",
        },
        channelsSubscribedCount: {
          $size: "$subscribedTo",
        },
        isSubscribed: {
          $cond: {
            if: { $in: [req.user?._id, "$subscribers.subscriber"] },
            then: true,
            else: false,
          },
        },
      },
    },
    {
      $project: {
        fullname: 1,
        username: 1,
        subscribersCount: 1,
        channelsSubscribedCount: 1,
        isSubscribed: 1,
        avatar: 1,
        coverImage: 1,
        email: 1,
      },
    },
  ]);

  //   चैनल की जांच करें
  if (!channel || channel.length === 0) {
    throw new ApiError(404, "चैनल मौजूद नहीं है");
  }

  // चैनल लौटाएँ और प्रतिक्रिया भेजें
  return res
    .status(200)
    .json(
      new ApiResponse(
        200,
        channel[0],
        "उपयोगकर्ता चैनल सफलतापूर्वक प्राप्त किया गया"
      )
    );
});

// ---------------------------------------------------------------------------------------------
//                       get watch History
// ---------------------------------------------------------------------------------------------

const getWatchHistory = asyncHandler(async (req, res) => {
  const user = await User.aggregate([
    {
      $match: {
        _id: new mongoose.Types.ObjectId(req.user._id),
      },
    },
    {
      $lookup: {
        from: "videos",
        localField: "watchHistory",
        foreignField: "_id",
        as: "watchHistory",
        pipeline: [
          {
            $lookup: {
              from: "users",
              localField: "owner",
              foreignField: "_id",
              as: "owner",
              pipeline: [
                {
                  $project: {
                    fullname: 1,
                    username: 1,
                    avatar: 1,
                  },
                },
              ],
            },
          },
          {
            $addFields: {
              owner: {
                $first: "$owner",
              },
            },
          },
        ],
      },
    },
  ]);

  return res
    .status(200)
    .json(
      new ApiResponse(
        200,
        user[0].watchHistory,
        "Watch history fetched successfully"
      )
    );
});

// ---------------------------------------------------------------------------------------------
// export all controller
// ---------------------------------------------------------------------------------------------
export {
  loginUser,
  logoutUser,
  registerUser,
  refreshAccessToken,
  changeCurrentPassword,
  getCurrentUser,
  updateAccountDetails,
  updateUserAvatar,
  updateUserCoverImage,
  getUserChannelProfile,
  getWatchHistory,
};
