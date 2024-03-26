const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcrypt');
const { generateTokenAndSetCookie } = require('../utils/generateToken.js');
const path = require('path');
const fs = require('fs');
const jwt = require("jsonwebtoken");
const prisma = new PrismaClient();

exports.signUpUser = async (req, res) => {
  if (!req.files || Object.keys(req.files).length === 0 || !req.files.file) {
    return res.status(400).json({ message: 'Please upload a profile picture' });
  }
  const {
    fullName,
    username,
    password,
    confirmPassword,
    email,
    address,
    phone,
  } = req.body;
  const file = req.files.file;
  const fileSize = file.data.length;
  const ext = path.extname(file.name);
  const fileName = file.md5 + '_' + Date.now() + ext;
  const url = `${req.protocol}://localhost:5000/images/${fileName}`;
  const allowedType = ['.png', '.jpg', '.jpeg'];

  if (!fullName || !username || !password || !confirmPassword || !email || !address || !phone) {
    return res.status(400).json({ message: 'Please fill in all fields' });
  }

  if (password !== confirmPassword) {
    return res.status(400).json({ message: 'Password does not match' });
  }

  if(password.length < 6) {
    return res.status(400).json({ message: 'Password must be at least 6 characters' });
  }

  if (!allowedType.includes(ext.toLowerCase())) {
    res.status(422).json({ msg: 'Invalid Images' });
  }

  if (fileSize > 2000000) {
    res.status(422).json({ msg: 'Image must be less than 2mb' });
  }

  const user = await prisma.users.findUnique({
    where: {
      username: username,
    },
  });

  const emailUser = await prisma.users.findUnique({
    where: {
      email: email,
    },
  });

  if (user || emailUser) {
    return res
      .status(400)
      .json({ message: 'Username or email already exists' });
  }

  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);

  file.mv(`src/public/images/${fileName}`, async (err) => {
    if (err) {
      return res.status(500).json({ message: err.message });
    }
    try {
      const newUser = await prisma.users.create({
        data: {
          fullName,
          username,
          password: hashedPassword,
          email,
          address,
          phone,
          profilePic: fileName,
          picUrl: url,
        },
      });

      if (newUser) {
        //generate jwt token
        generateTokenAndSetCookie(newUser.id, res);

        res.status(201).json({
          id: newUser.id,
          fullName: newUser.fullName,
          username: newUser.username,
          email: newUser.email,
          address: newUser.address,
          phone: newUser.phone,
          roles: newUser.roles,
          event: newUser.event,
          profilePic: newUser.profilePic,
        });
      } else {
        res.status(500).json({ message: 'Invalid user data' });
      }
    } catch (error) {
      console.log(error);
      res.status(500).json({ message: error.message });
    }
  });
};

exports.loginUser = async (req, res) => {
  try {
    const { username, password } = req.body;

    const user = await prisma.users.findUnique({
      where: {
        username: username,
      },
    });

    const isMatch = await bcrypt.compare(password, user?.password || '');

    if (!user || !isMatch) {
      return res
        .status(400)
        .json({ message: 'Username or Password incorrect' });
    }

    generateTokenAndSetCookie(user.id, res);

    res.status(200).json({
      id: user.id,
      fullName: user.fullName,
      username: user.username,
      email: user.email,
      address: user.address,
      phone: user.phone,
      roles: user.roles,
      event: user.event,
      profilePic: user.profilePic,
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: error.message });
  }
};

exports.getMe = async (req, res) => {
  try {
    const token = req.cookies.token;
    if(!token) {
      return res.json({ message: "Unauthorized" });
    }
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if(!decoded) {
      return res.json({ message: "Unauthorized" });
    }
    const user = await prisma.users.findUnique({
      where: {
        id: decoded.userId
      }
    })
    if(!user) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    generateTokenAndSetCookie(user.id, res);
    res.status(200).json(user)
  }catch (error) {
    res.status(500).json({message: 'Internal server error'})
  }
}

exports.logoutUser = (req, res) => {
  try {
    res.clearCookie('token');
    res.status(200).json({ message: 'Logged out successfully' });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: error.message });
  }
};
