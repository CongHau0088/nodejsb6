var express = require('express');
var router = express.Router();
let bcrypt = require('bcrypt');
let userSchema = require('../models/users');
let userController = require('../controllers/users');
let BuildQueries = require('../Utils/BuildQuery');
let { check_authentication, check_authorization } = require('../Utils/check_auth');
let constants = require('../Utils/constants');

router.get('/', async function (req, res, next) {
  let queries = req.query;
  let users = await userSchema.find(BuildQueries.QueryUser(queries)).populate('role');
  res.send(users);
});

router.get('/:id', check_authentication, async function (req, res, next) {
  try {
    if (req.user._id == req.params.id) {
      let user = await userSchema.findById(req.params.id).populate('role');
      res.status(200).send({
        success: true,
        data: user
      });
    } else {
      throw new Error("Bạn không có quyền truy cập");
    }
  } catch (error) {
    next(error);
  }
});

// Route: Reset password (chỉ Admin mới thực hiện được)
router.get('/auth/resetPassword/:id', check_authentication, check_authorization(constants.ADMIN_PERMISSION), async function (req, res, next) {
  try {
    const userId = req.params.id;
    const user = await userSchema.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'Người dùng không tồn tại' });
    }

    // Băm mật khẩu trước khi lưu
    const hashedPassword = await bcrypt.hash('123456', 10);
    user.password = hashedPassword;
    await user.save();

    res.status(200).json({ message: 'Mật khẩu đã được reset về 123456' });
  } catch (error) {
    next(error);
  }
});

// Route: Đổi mật khẩu
router.post('/auth/changePassword', check_authentication, async function (req, res, next) {
  try {
    const { currentPassword, newPassword } = req.body;
    const user = await userSchema.findById(req.user._id);
    if (!user) {
      return res.status(404).json({ message: 'Người dùng không tồn tại' });
    }

    // Kiểm tra mật khẩu hiện tại
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Mật khẩu hiện tại không đúng' });
    }

    // Kiểm tra độ mạnh của mật khẩu mới (có ít nhất 6 ký tự)
    if (newPassword.length < 6) {
      return res.status(400).json({ message: 'Mật khẩu mới phải có ít nhất 6 ký tự' });
    }

    // Băm mật khẩu mới và cập nhật
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();

    res.status(200).json({ message: 'Mật khẩu đã được thay đổi thành công' });
  } catch (error) {
    next(error);
  }
});

router.put('/:id', async function (req, res, next) {
  try {
    let body = req.body;
    let user = await userSchema.findById(req.params.id).populate({ path: "role", select: "roleName" });

    if (user) {
      let allowField = ["password", "email", "fullName", "avatarUrl"];
      for (const key of Object.keys(body)) {
        if (allowField.includes(key)) {
          if (key === "password") {
            // Nếu cập nhật mật khẩu thì phải băm trước khi lưu
            body[key] = await bcrypt.hash(body[key], 10);
          }
          user[key] = body[key];
        }
      }
      await user.save();
      res.status(200).send({
        success: true,
        data: user
      });
    }
  } catch (error) {
    next(error);
  }
});

module.exports = router;
