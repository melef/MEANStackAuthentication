// angular js code to control Products list
var meanStackTrial = angular.module("MeanStackTrial", []);

meanStackTrial.controller('MeanStackController', function ($http) {
    var productApp = this;
    var url = "http://localhost:4000";

    function loadProducts() {
        $http.get(url).success(function (products) {
            console.log('fetching all products..')
            productApp.products = products;

        })
    }

    productApp.saveProduct = function (productName, productQuantity) {
        $http.post(url + "/add", {name: productName, quantity: productQuantity}).success(function () {
            loadProducts();
        });
    }

    loadProducts();
})



