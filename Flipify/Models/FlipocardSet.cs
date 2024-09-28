namespace Flipify.Models
{
    public class FlipcardSet
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public Guid UserId { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public string BaseLanguage { get; set; }
        public string ForeignLanguage { get; set; }
        public string Name { get; set; }

        public ICollection<Flipcard> Flipcards { get; set; } = new List<Flipcard>();
    }
}
