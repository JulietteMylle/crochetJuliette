<?php

namespace App\Entity;

use App\Repository\PatronRepository;
use Doctrine\Common\Collections\ArrayCollection;
use Doctrine\Common\Collections\Collection;
use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity(repositoryClass: PatronRepository::class)]
class Patron
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\Column(length: 255)]
    private ?string $name = null;

    #[ORM\Column(length: 255)]
    private ?string $description = null;

    /**
     * @var Collection<int, PartiePatron>
     */
    #[ORM\OneToMany(targetEntity: PartiePatron::class, mappedBy: 'id_patron', orphanRemoval: true)]
    private Collection $partiePatrons;

    public function __construct()
    {
        $this->partiePatrons = new ArrayCollection();
    }

    public function getId(): ?int
    {
        return $this->id;
    }

    public function setId(int $id): static
    {
        $this->id = $id;

        return $this;
    }

    public function getName(): ?string
    {
        return $this->name;
    }

    public function setName(string $name): static
    {
        $this->name = $name;

        return $this;
    }

    public function getDescription(): ?string
    {
        return $this->description;
    }

    public function setDescription(string $description): static
    {
        $this->description = $description;

        return $this;
    }

    /**
     * @return Collection<int, PartiePatron>
     */
    public function getPartiePatrons(): Collection
    {
        return $this->partiePatrons;
    }

    public function addPartiePatron(PartiePatron $partiePatron): static
    {
        if (!$this->partiePatrons->contains($partiePatron)) {
            $this->partiePatrons->add($partiePatron);
            $partiePatron->setIdPatron($this);
        }

        return $this;
    }

    public function removePartiePatron(PartiePatron $partiePatron): static
    {
        if ($this->partiePatrons->removeElement($partiePatron)) {
            // set the owning side to null (unless already changed)
            if ($partiePatron->getIdPatron() === $this) {
                $partiePatron->setIdPatron(null);
            }
        }

        return $this;
    }
}
