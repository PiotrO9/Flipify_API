namespace Flipify.DTOs
{
    public class FlipcardDto
    {
        public Guid Id { get; set; }
        public Guid FlipcardSetId { get; set; }
        public string NativeWord { get; set; }
        public string ForeignWord { get; set; }
        public string NativeWordExample { get; set; }
        public string ForeignWordExample { get; set; }
        public DateTime LastReviewDate { get; set; }
        public DateTime NextReviewDate { get; set; }
        public int IntervalDays { get; set; }
        public decimal Ef { get; set; }
        public int AttemptCount { get; set; }
    }

}
