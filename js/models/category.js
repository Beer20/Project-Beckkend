const { DataTypes } = require('sequelize');
const sequelize = require('./index');
const Category = sequelize.define('Category', {
    
 categoryID: {
 type: DataTypes.INTEGER,
 autoIncrement: true,
 primaryKey: true
 },
 categoryName: {
 type: DataTypes.STRING,
 allowNull: false
 },
 description: {
 type: DataTypes.STRING,
 allowNull: true
 }
},
 {
 timestamps: false
});
25
module.exports = Category;
