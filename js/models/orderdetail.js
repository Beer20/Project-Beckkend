// models/orderDetail.js
const { DataTypes } = require('sequelize');
const sequelize = require('./index');
const Order = require('./order');
const Product = require('./product');
const OrderDetail = sequelize.define('OrderDetail', {
 orderDetailID: {
 type: DataTypes.INTEGER,
 primaryKey: true,
 autoIncrement: true

 },
 orderID: {
 type: DataTypes.INTEGER,
 allowNull: false,
 references: {
    model: Order,
    key: "orderID"
 }
 },

 productID: {
 type: DataTypes.INTEGER,
 allowNull: false,
 references: {
    model: Product,
    key: "productID"
 }
 },
 quantity: {
 type: DataTypes.INTEGER,
 allowNull: false
 }
});

//relasi orderdetail dengan product
OrderDetail.belongsTo(Product, { foreignKey: 'productID' });
Product.hasMany(Order, { foreignKey: 'productID' });

//relasi orderdetail dengan order
OrderDetail.belongsTo(Order, { foreignKey: 'orderID' });
Order.hasMany(OrderDetail, { foreignKey: 'orderID' });


module.exports = OrderDetail;