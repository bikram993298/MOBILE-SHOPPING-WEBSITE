export const registerFormControls = [
  {
    name: "userName",
    label: "User Name",
    placeholder: "Enter your user name",
    componentType: "input",
    type: "text",
  },
  {
    name: "email",
    label: "Email",
    placeholder: "Enter your email",
    componentType: "input",
    type: "email",
  },
  {
    name: "password",
    label: "Password",
    placeholder: "Enter your password",
    componentType: "input",
    type: "password",
  },
];

export const loginFormControls = [
  {
    name: "email",
    label: "Email",
    placeholder: "Enter your email",
    componentType: "input",
    type: "email",
  },
  {
    name: "password",
    label: "Password",
    placeholder: "Enter your password",
    componentType: "input",
    type: "password",
  },
];

export const addProductFormElements = [
  {
    label: "Title",
    name: "title",
    componentType: "input",
    type: "text",
    placeholder: "Enter product title",
  },
  {
    label: "Description",
    name: "description",
    componentType: "textarea",
    placeholder: "Enter product description",
  },
  {
    label: "Category",
    name: "category",
    componentType: "select",
    options: [
      { id: "smartphones", label: "Smartphones" },
      { id: "tablets", label: "Tablets" },
      { id: "accessories", label: "Accessories" },
      { id: "wearables", label: "Wearables" },
      { id: "gadgets", label: "Gadgets" },
      { id: "new-arrivals", label: "New Arrivals" },
      { id: "deals", label: "Deals & Offers" },
    ],
    
  },
  {
    label: "Brand",
    name: "brand",
    componentType: "select",
    options: [
      { id: "realme", label: "Realme" },
      { id: "redmi", label: "Redmi" },
      { id: "vivo", label: "Vivo" },
      { id: "samsung", label: "Samsung" },
      { id: "oppo", label: "Oppo" },
      { id: "apple", label: "Apple" },
    
    ],
  },
  {
    label: "Price",
    name: "price",
    componentType: "input",
    type: "number",
    placeholder: "Enter product price",
  },
  {
    label: "Sale Price",
    name: "salePrice",
    componentType: "input",
    type: "number",
    placeholder: "Enter sale price (optional)",
  },
  {
    label: "Total Stock",
    name: "totalStock",
    componentType: "input",
    type: "number",
    placeholder: "Enter total stock",
  },
];

export const shoppingViewHeaderMenuItems = [
  {
    id: "home",
    label: "Home",
    path: "/shop/home",
  },
  {
    id: "products",
    label: "Products",
    path: "/shop/listing",
  },
  {
    id: "smartphones",
    label: "Smartphones",
    path: "/shop/listing",
  },
  {
    id: "tablets",
    label: "Tablets",
    path: "/shop/listing",
  },
  {
    id: "accessories",
    label: "Accessories",
    path: "/shop/listing",
  },
  {
    id: "wearables",
    label: "Wearables",
    path: "/shop/listing",
  },
  {
    id: "gadgets",
    label: "Gadgets",
    path: "/shop/listing",
  },
  {
    id: "new Arrivals",
    label: "New Arrivals",
    path: "/shop/listing",
  },
  {
    id: "search",
    label: "Search",
    path: "/shop/search",
  },
];

export const categoryOptionsMap = {
  smartphones: "Smartphones",
  tablets: "Tablets",
  accessories: "Accessories",
  wearables: "Wearables",
  gadgets: "Gadgets",
  newArrivals: "New Arrivals",
  deals: "Deals & Offers",
};

export const brandOptionsMap = {
  realme: "Realme",
  redmi: "Redmi",
  vivo: "Vivo",
  samsung: "Samsung",
  oppo: "Oppo",
  apple:"Apple",
};

export const filterOptions = {
  category: [
    { id: "smartphones", label: "Smartphones" },
    { id: "tablets", label: "Tablets" },
    { id: "accessories", label: "Accessories" },
    { id: "wearables", label: "Wearables" },
    { id: "gadgets", label: "Gadgets" },
    { id: "new-arrivals", label: "New Arrivals" },
    { id: "deals", label: "Deals & Offers" },
  ],


  brand: [
    { id: "realme", label: "Realme" },
    { id: "redmi", label: "Redmi" },
    { id: "vivo", label: "Vivo" },
    { id: "samsung", label: "Samsung" },
    { id: "oppo", label: "Oppo" },
    { id: "apple", label: "Apple" },
  ],
};

export const sortOptions = [
  { id: "price-lowtohigh", label: "Price: Low to High" },
  { id: "price-hightolow", label: "Price: High to Low" },
  { id: "title-atoz", label: "Title: A to Z" },
  { id: "title-ztoa", label: "Title: Z to A" },
];

export const addressFormControls = [
  {
    label: "Address",
    name: "address",
    componentType: "input",
    type: "text",
    placeholder: "Enter your address",
  },
  {
    label: "City",
    name: "city",
    componentType: "input",
    type: "text",
    placeholder: "Enter your city",
  },
  {
    label: "Pincode",
    name: "pincode",
    componentType: "input",
    type: "text",
    placeholder: "Enter your pincode",
  },
  {
    label: "Phone",
    name: "phone",
    componentType: "input",
    type: "text",
    placeholder: "Enter your phone number",
  },
  {
    label: "Notes",
    name: "notes",
    componentType: "textarea",
    placeholder: "Enter any additional notes",
  },
];
