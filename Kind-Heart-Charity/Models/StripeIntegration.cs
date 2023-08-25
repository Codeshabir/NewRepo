using Microsoft.AspNetCore.Mvc;
using Stripe.Checkout;
using Stripe;

namespace Kind_Heart_Charity.Models
{
    public class StripeIntegration
    {
        public async Task<string> ChecoutStripe(int amount)
        {
            StripeConfiguration.ApiKey = "sk_test_4eC39HqLyjWDarjtT1zdp7dc";

            var options = new SessionCreateOptions
            {
                PaymentMethodTypes = new List<string>
            {
                "card"
            },
                LineItems = new List<SessionLineItemOptions>
            {
                new SessionLineItemOptions
                {
                    PriceData = new SessionLineItemPriceDataOptions
                    {
                        UnitAmount = amount*100, // amount in cents
                        Currency = "usd",
                        ProductData = new SessionLineItemPriceDataProductDataOptions
                        {
                            Name = "Payment Integrate"
                        }
                    },
                    Quantity = 1
                }
            },
                Mode = "payment",
                SuccessUrl = "https://your-website.com/success",
                CancelUrl = "https://your-website.com/cancel"
            };

            var service = new SessionService();
            var session = service.Create(options);
            return ( session.Url);
        }
    }
}
