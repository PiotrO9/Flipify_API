namespace Flipify.DTOs
{
    public class CreateFlipcardDto
    {
        public Guid FlipcardSetId { get; set; }
        public string NativeWord { get; set; }
        public string ForeignWord { get; set; }
        public string NativeWordExample { get; set; }
        public string ForeignWordExample { get; set; }
    }

}
