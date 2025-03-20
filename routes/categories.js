const { fail } = require('assert');
var express = require('express');
var router = express.Router();
let categorySchema = require('../models/catgories')
let BuildQueies = require('../Utils/BuildQuery')

//http://localhost:3000/products?name=iph&price[$gte]=1600&price[$lte]=3000
/* GET users listing. */
router.get('/', async function(req, res, next) {
  let queries = req.query;
  let categories = await categorySchema.find({});
  res.send(categories);
});
router.get('/:id', async function(req, res, next) {
  try {
    let category = await categorySchema.findById(req.params.id);
    res.status(200).send({
      success:true,
      data:category
    });
  } catch (error) {
    res.status(404).send({
      success:fail,
      message:error.message
    })
  }
});
router.post('/', async function(req, res, next) {
  let body = req.body;
  console.log(body);
  let newCategory = new categorySchema({
    categoryName: body.categoryName,
  })
  await newCategory.save()
  res.send(newCategory);
});
router.put('/:id', async function(req, res, next) {
  try {
    let body = req.body;
    let category = await newCategory.findByIdAndUpdate(req.params.id,
      body,{new:true});
    res.status(200).send({
      success:true,
      data:category
    });
  } catch (error) {
    res.status(404).send({
      success:fail,
      message:error.message
    })
  }
  // let body = req.body;
  // console.log(body);
  // let newProduct = new productSchema({
  //   productName: body.productName,
  //   price: body.price,
  //   quantity: body.quantity,
  //   categoryID: body.category
  // })
  // await newProduct.save()
  // res.send(newProduct);
});


module.exports = router;
