const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcrypt');
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
  const allowedType = ['.png', '.jpg', '.jpeg', '.webp'];

  if (!fullName || !username || !password || !confirmPassword || !email || !address || !phone) {
    return res.status(400).json({ message: 'Semua data harus diisi' });
  }

  if (password !== confirmPassword) {
    return res.status(400).json({ message: 'Password does not match' });
  }

  if(password.length < 6) {
    return res.status(400).json({ message: 'Password Minimal 6 characters' });
  }

  if (!allowedType.includes(ext.toLowerCase())) {
    return res.status(422).json({ message: 'Format gambar tidak didukung' });
  }

  if (fileSize > 2000000) {
    return res.status(422).json({ message: 'Ukuran gambar tidak boleh lebih dari 2Mb' });
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
  });
  try {
    const refresh_token = jwt.sign({ username }, process.env.JWT_SECRET, {
      expiresIn: '15d',
    });
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
        refreshToken: refresh_token
      },
    });
    if (newUser) {
      return res.status(201).json(newUser);
    } else {
      return res.status(500).json({ message: 'Invalid user data' });
    }
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: error.message });
  }
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

    res.status(200).json(user);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

exports.logoutUser = async(req, res) => {
  try {
    const user = await prisma.users.findUnique({
      where: {
        username: req.user.username
      }
    })
    if(!user) {
      return res.status(403).json({ message: "User not found" });
    }

    await prisma.users.update({
      where: {
        id: user.id
      },
      data: {
        refreshToken: null
      }
    })
    return res.status(200).json({ message: 'Logged out successfully' });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: error.message });
  }
};
