// models/order.js
const { DataTypes } = require('sequelize');
const sequelize = require('./index');
const customer = require('./customer');
const employee = require('./employee');
const shipper = require('./shipper');
const Customer = require('./customer');

const Order = sequelize.define('Order', {

 orderID: {
 type: DataTypes.INTEGER,
 primaryKey: true,
 autoIncrement: true
 },

 customerID: {
 type: DataTypes.INTEGER,
 allowNull: false,
 references: {
    model: customer,
    key: "customerID"
 }
 },

 firstName: {
 type: DataTypes.STRING,
 allowNull: false
 },

 employeeID: {
 type: DataTypes.INTEGER,
 allowNull: false,
 references: {
    model: employee,
    key: "employeeID"
 }
 },

 orderDate: {
 type: DataTypes.DATE,
 allowNull: false
 },

 shipperID: {
 type: DataTypes.INTEGER,
 allowNull: false,
 references: {
    model: shipper,
    key: "shipperID"
 }
 }

});

//relasi order dengan customer
Order.belongsTo(Customer, { foreignKey: 'customerID' });
Customer.hasMany(Order, { foreignKey: 'customerID' });


//relasi order dengan shipper
Order.belongsTo(shipper, { foreignKey: 'shipperID' });
shipper.hasMany(Order, { foreignKey: 'shipperID' });

//relasi order dengan employee
Order.belongsTo(employee, { foreignKey: 'employeeID' });
employee.hasMany(Order, { foreignKey: 'employeeID' });



module.exports = Order;


