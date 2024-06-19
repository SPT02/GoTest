package models


type User struct {
	ID         int     `json:"id"`
	Username   string  `json:"username"`
	Password   string  `json:"password"`
	Name       string  `json:"name"`
	Account_no string  `json:"account_no"`
	Credit     float64 `json:"credit"`
}
