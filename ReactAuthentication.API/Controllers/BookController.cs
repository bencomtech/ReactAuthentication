using System.Collections.Generic;
using System.Web.Http;

namespace ReactAuthentication.API.Controllers
{
    [RoutePrefix("api/Books")]
    public class BookController : ApiController
    {
        [Authorize]
        [Route("")]
        public IHttpActionResult Get()
        {
            List<Book> books = new List<Book>()
            {
                new Book() { BookID = 1, BookName = "Book 1" },
                new Book() { BookID = 2, BookName = "Book 2" }
            };

            return Ok(books);
        }
    }

    public class Book
    {
        public int BookID { get; set; }
        public string BookName { get; set; }
    }
}
