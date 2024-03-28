const jwt = require("jsonwebtoken")
const dotenv = require("dotenv")
const {PrismaClient} = require("@prisma/client")

const prisma = new PrismaClient()

dotenv.config()

exports.generateTokenAndSetCookie = async(userId,res) => {
  const token = jwt.sign({ userId }, process.env.JWT_SECRET, {
    expiresIn: "15d",
  })

  await prisma.users.update({
    where: {
      id: userId
    },
    data: {
      refreshToken: token
    }
  })


  res.cookie("token", token, {
    httpOnly: true,
    maxAge: 15 * 24 * 60 * 60 * 1000,
    sameSite: "strict",
    secure: process.env.NODE_ENV !== "development",
  })
}

