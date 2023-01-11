# Image_Monitor
Deterministic and scalable solution for vulnerable images leading to Supply Chain Attacks


**Instructions**

Explore the solution (marked for FURTHER EXPLORATION) in more detail with the same group. Describe your solution/results (~5 pages) Sections: Abstract, Introduction (with Motivation), Background, Threat Model, Design, Implementation, Evaluation, Related Solutions, Conclusion, References

Important points:

Must have enough detail to be understandable

Evaluate the practicality of your solution Use real data sets if possible. Extra credit: based upon completeness / scope

Do not plagiarize!!! Be clear about sources (citations)

Your submission must be in PDF format only. Specify your group number in the filename

**Abstract**

One method that cybercriminals have used to exploit software supply chains has been by
discretely inserting malicious container images into registries or injecting malicious code directly
into vulnerable container images.

The objective of this project is to elaborate on the threats associated with vulnerable container
images and the risks they impose. Research focused on the illegal modification of container images
within a registry and different methods to secure the various images. The solution to be detailed is a
Python based image monitoring system.

The image monitor was successfully implemented to maintain the pristineness of the container
images deterministically. The solution works under the principles of high availability and high
scalability. It applies user-defined policies on the filesystem to prevent any alteration of the private
