package models

type TransferHistory struct {
	ID         int     `json:"id"`
	timestamp   string  `json:"timestamp"`
	Sender_UserId   string  `json:"sender_userid"`
	Sender_UserAccountNo   string  `json:"sender_useraccountno"`
	Receiver_UserId       string  `json:"receiver_userid"`
	Receiver_UserAccountNo       string  `json:"receiver_useraccountno"`
	amount float64  `json:"amount"`
}
