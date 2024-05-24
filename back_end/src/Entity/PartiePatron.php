<?php

namespace App\Entity;

use App\Repository\PartiePatronRepository;
use Doctrine\Common\Collections\ArrayCollection;
use Doctrine\Common\Collections\Collection;
use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity(repositoryClass: PartiePatronRepository::class)]
class PartiePatron
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\Column(length: 255)]
    private ?string $name = null;

    #[ORM\ManyToOne(inversedBy: 'partiePatrons')]
    #[ORM\JoinColumn(nullable: false)]
    private ?Patron $id_patron = null;

    /**
     * @var Collection<int, UserPartiePatron>
     */
    #[ORM\OneToMany(targetEntity: UserPartiePatron::class, mappedBy: 'id_PartiePatron', orphanRemoval: true)]
    private Collection $userPartiePatrons;

    public function __construct()
    {
        $this->userPartiePatrons = new ArrayCollection();
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

    public function getIdPatron(): ?Patron
    {
        return $this->id_patron;
    }

    public function setIdPatron(?Patron $id_patron): static
    {
        $this->id_patron = $id_patron;

        return $this;
    }

    /**
     * @return Collection<int, UserPartiePatron>
     */
    public function getUserPartiePatrons(): Collection
    {
        return $this->userPartiePatrons;
    }

    public function addUserPartiePatron(UserPartiePatron $userPartiePatron): static
    {
        if (!$this->userPartiePatrons->contains($userPartiePatron)) {
            $this->userPartiePatrons->add($userPartiePatron);
            $userPartiePatron->setIdPartiePatron($this);
        }

        return $this;
    }

    public function removeUserPartiePatron(UserPartiePatron $userPartiePatron): static
    {
        if ($this->userPartiePatrons->removeElement($userPartiePatron)) {
            // set the owning side to null (unless already changed)
            if ($userPartiePatron->getIdPartiePatron() === $this) {
                $userPartiePatron->setIdPartiePatron(null);
            }
        }

        return $this;
    }
}
